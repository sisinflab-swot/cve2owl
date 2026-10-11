from collections.abc import Callable, Iterator, Mapping, Sequence, Set as AbstractSet
from typing import Any, cast, overload

import cowl

from .jsonio import JSONObject, JSONValue, get_as
from .naming import Namespace

type ExpressionOrRange = cowl.ClassExpression | cowl.DataRange

# Translates a definition in place of the default translation.
type Override = Callable[[SchemaTranslator, str, JSONObject], ExpressionOrRange]

# Guards against $refs that cannot be resolved
MAX_REF_RESOLUTION_PASSES = 10


class UnresolvedRefError(Exception):
    pass


def new_ontology(ns: Namespace) -> cowl.Ontology:
    onto = cowl.Ontology()
    onto.set_iri(ns.iri)
    onto.prefix_map[ns.prefix] = ns.namespace
    return onto


class SchemaTranslator:
    def __init__(
        self,
        ns: Namespace,
        *,
        overrides: Mapping[str, Override] | None = None,
        ignore: AbstractSet[str] = frozenset(),
    ) -> None:
        self.ns = ns
        self.onto = new_ontology(ns)
        self.overrides = overrides or {}
        self.ignore = ignore

    def add(self, axiom: cowl.Axiom) -> None:
        if axiom not in self.onto:
            self.onto.add(axiom)

    def translate(self, *definitions: Mapping[str, JSONObject]) -> cowl.Ontology:
        for _ in range(MAX_REF_RESOLUTION_PASSES):
            unresolved = False
            for defs in definitions:
                for name, schema in defs.items():
                    try:
                        self.translate_definition(name, schema)
                    except UnresolvedRefError:
                        unresolved = True
            if not unresolved:
                return self.onto
        msg = f"the $ref resolution loop did not converge in {MAX_REF_RESOLUTION_PASSES} passes"
        raise RuntimeError(msg)

    def translate_definition(self, name: str, schema: JSONObject) -> None:
        if name in self.ignore:
            return

        if override := self.overrides.get(name):
            obj = override(self, name, schema)
        else:
            obj = self.owl_object(schema)

        if cowl.is_data_range(obj):
            self.add(self.ns.datatype(name).is_defined_as(obj))
            return

        if not isinstance(obj, cowl.ObjectIntersectionOf):
            self.add(self.ns.cls(name).is_a(obj))
            return

        for operand in obj.operands():
            self.add(self.ns.cls(name).is_a(operand))

    def resolve_ref(self, ref: str) -> cowl.Class | cowl.Datatype:
        if (index := ref.rfind("/definitions/")) == -1:
            msg = f"Unsupported $ref format: {ref}"
            raise ValueError(msg)

        name = ref[index + len("/definitions/") :]

        if (cls := self.ns.cls(name)) in self.onto:
            return cls
        if (dt := self.ns.datatype(name)) in self.onto:
            return dt

        msg = f"Unresolved $ref: {ref}"
        raise UnresolvedRefError(msg)

    def owl_object(self, schema: JSONObject) -> ExpressionOrRange:
        if ref := get_as(schema, "$ref", str):
            return self.resolve_ref(ref)

        if (const := get_as(schema, "const", str)) is not None:
            return cowl.one_of(const)

        # TODO: handle mixed boolean and type expressions.
        if (type_expr := self.type_expression(schema)) != cowl.owl.thing:
            return type_expr
        return self.bool_expression(schema)

    def type_expression(self, schema: JSONObject) -> ExpressionOrRange:
        match get_as(schema, "type", str):
            case "boolean":
                return cowl.xsd.boolean
            case "integer":
                return integer_restriction(schema)
            case "number":
                return number_restriction(schema)
            case "string":
                return string_restriction(schema)
            case "array":
                return self.array_restriction(schema)
            case _:
                return self.object_restriction(schema)

    def bool_expression(self, schema: JSONObject) -> ExpressionOrRange:
        if all_of := get_as(schema, "allOf", list[JSONObject]):
            return intersection(*(self.owl_object(item) for item in all_of))
        if any_of := get_as(schema, "anyOf", list[JSONObject]):
            return union(*(self.owl_object(item) for item in any_of))
        if one_of := get_as(schema, "oneOf", list[JSONObject]):
            return union(*(self.owl_object(item) for item in one_of))
        return cowl.owl.thing

    def array_restriction(self, schema: JSONObject) -> ExpressionOrRange:
        if items := get_as(schema, "items", JSONObject):
            return self.owl_object(items)
        return cowl.owl.thing

    def object_restriction(self, schema: JSONObject) -> ExpressionOrRange:
        if props := get_as(schema, "properties", dict[str, JSONObject]):
            return intersection(
                *(
                    self.property_value_restriction(pname, pschema)
                    for pname, pschema in props.items()
                ),
            )
        return cowl.owl.thing

    def property_value_restriction(
        self,
        name: str,
        schema: JSONObject,
        *,
        min_: int = 0,
        max_: int | None = None,
    ) -> cowl.ClassExpression:
        filler = self.owl_object(schema)
        operands: list[cowl.ClassExpression] = []

        if cowl.is_class_expression(filler):
            prop = self.ns.object_property(name)
            if filler != cowl.owl.thing:
                operands.append(prop.only(filler))
        else:
            prop = self.ns.data_property(name)
            operands.append(prop.only(filler))

        if min_ == max_:
            operands.append(prop.exactly(min_))
        else:
            if min_ > 0:
                operands.append(prop.min(min_))
            if max_ is not None:
                operands.append(prop.max(max_))

        return intersection(*operands)


# Override that turns an enum type into a class enumerated by named individuals.
def enum_as_class(
    translator: SchemaTranslator,
    base_class_name: str,
    schema: JSONObject,
) -> ExpressionOrRange:
    if (enum := get_as(schema, "enum", list[str])) is None:
        msg = f"Expected 'enum' in schema: {schema}"
        raise ValueError(msg)

    ns = translator.ns
    base_class = ns.cls(base_class_name)
    individuals = [ns.enum_individual(base_class_name, value) for value in enum]

    for i in individuals:
        translator.add(i.is_a(base_class))

    return cowl.one_of(*individuals)


def integer_restriction(schema: JSONObject) -> cowl.DataRange:
    if enum := get_as(schema, "enum", list[int]):
        return cowl.one_of(*enum)
    if any(key in schema for key in ("minimum", "maximum")):
        return cowl.xsd.integer.that_has(
            value_ge=get_as(schema, "minimum", int),
            value_le=get_as(schema, "maximum", int),
        )
    return cowl.xsd.integer


def number_restriction(schema: JSONObject) -> cowl.DataRange:
    if enum := get_as(schema, "enum", list[float]):
        return cowl.one_of(*(cowl.xsd.decimal(v) for v in enum))
    if any(key in schema for key in ("minimum", "maximum")):
        return cowl.xsd.decimal.that_has(
            value_ge=get_as(schema, "minimum", float),
            value_le=get_as(schema, "maximum", float),
        )
    return cowl.xsd.decimal


def string_restriction(schema: JSONObject) -> ExpressionOrRange:
    if enum := get_as(schema, "enum", list[str]):
        return cowl.one_of(*enum)
    if const := get_as(schema, "const", str):
        return cowl.one_of(const)
    if any(key in schema for key in ("minLength", "maxLength", "pattern")):
        return cowl.xsd.string.that_has(
            min_length=get_as(schema, "minLength", int),
            max_length=get_as(schema, "maxLength", int),
            pattern=xsd_pattern(pattern) if (pattern := get_as(schema, "pattern", str)) else None,
        )
    return cowl.xsd.string


# Escapes valid in XML Schema regexes; other ECMAScript escapes of punctuation are literals.
XSD_ESCAPES = frozenset("nrt\\|.?*+(){}-[]^sSiIcCdDwWpP")

# A regex token, and whether it is an unescaped ^, $, (, ) or |.
type RegexToken = tuple[str, bool]


def xsd_pattern(pattern: str) -> str:
    # JSON Schema patterns are ECMAScript regexes, which match anywhere in the string unless
    # anchored. xsd:pattern is an XML Schema regex, which always matches the whole string, and where
    # ^ and $ are plain characters. Anchors are per alternative: "^a|b$" is "starts with a or ends
    # with b".
    branches: list[list[RegexToken]] = [[]]
    depth = 0
    for text, special in _regex_tokens(pattern):
        if special and text == "|" and depth == 0:
            branches.append([])
            continue
        if special and text in "()":
            depth += 1 if text == "(" else -1
        branches[-1].append((text, special))
    return "|".join(_xsd_branch(branch, pattern) for branch in branches)


def _xsd_branch(tokens: list[RegexToken], pattern: str) -> str:
    start = bool(tokens) and tokens[0] == ("^", True)
    end = len(tokens) > start and tokens[-1] == ("$", True)
    body = tokens[int(start) : len(tokens) - int(end)]
    if any(special and text in "^$" for text, special in body):
        msg = f"anchor inside a regex alternative: {pattern}"
        raise ValueError(msg)
    any_text = ".*"
    return ("" if start else any_text) + "".join(t for t, _ in body) + ("" if end else any_text)


def _regex_tokens(pattern: str) -> Iterator[RegexToken]:
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            yield _xsd_escape(pattern, i), False
            i += 2
        elif c == "[":
            text, i = _xsd_class(pattern, i)
            yield text, False
        elif pattern.startswith("(?:", i):
            # No non-capturing groups in XML Schema, and groups never capture anyway.
            yield "(", True
            i += 3
        elif pattern.startswith("(?", i):
            msg = f"unsupported regex group: {pattern}"
            raise ValueError(msg)
        else:
            yield c, c in "^$()|"
            i += 1


def _xsd_class(pattern: str, i: int) -> tuple[str, int]:
    # Returns the class starting at i, and the index after it. ^ and $ are not anchors in a class.
    negated = pattern.startswith("[^", i)
    i += 2 if negated else 1
    atoms: list[str] = []
    while (c := pattern[i]) != "]":
        if c == "\\":
            atoms.append(_xsd_escape(pattern, i))
            i += 2
        else:
            atoms.append(c)
            i += 1
    chars: list[str] = []
    k = 0
    while k < len(atoms):
        if k + 2 < len(atoms) and atoms[k + 1] == "-" and atoms[k] != "-":
            chars.append(f"{atoms[k]}-{atoms[k + 2]}")
            k += 3
        else:
            # A "-" outside a range, as in [0-9-.], is literal in ECMAScript but not in XML Schema.
            # A [ must be escaped in XML Schema too.
            chars.append({"-": "\\-", "[": "\\["}.get(atoms[k], atoms[k]))
            k += 1
    return "[" + ("^" if negated else "") + "".join(chars) + "]", i + 1


def _xsd_escape(pattern: str, i: int) -> str:
    c = pattern[i + 1]
    if c in XSD_ESCAPES:
        return "\\" + c
    if c.isalnum():
        msg = f"unsupported regex escape \\{c}: {pattern}"
        raise ValueError(msg)
    return c


@overload
def intersection(*exprs: cowl.ClassExpression) -> cowl.ClassExpression: ...


@overload
def intersection(*exprs: cowl.DataRange) -> cowl.DataRange: ...


@overload
def intersection(*exprs: ExpressionOrRange) -> ExpressionOrRange: ...


def intersection(*exprs: ExpressionOrRange) -> ExpressionOrRange:
    filtered = [e for e in exprs if e != cowl.owl.thing]
    if not filtered:
        return cowl.owl.thing
    if len(filtered) == 1:
        return filtered[0]
    return cowl.intersection_of(*cast("list[cowl.ClassExpression]", filtered))


def union(*exprs: ExpressionOrRange) -> ExpressionOrRange:
    if not exprs:
        return cowl.owl.thing
    if len(exprs) == 1:
        return exprs[0]
    return cowl.union_of(*cast("list[cowl.ClassExpression]", exprs))


def hoist_definition(schema: dict[str, Any], path: Sequence[str], name: str) -> None:
    # Moves the inline subschema at path into the definitions, so it becomes a named class.
    *parents, key = path
    parent = schema
    for p in parents:
        parent = parent[p]
    schema["definitions"][name] = parent[key]
    parent[key] = {"$ref": f"#/definitions/{name}"}


def rewrite_openapi_refs(node: JSONValue) -> None:
    # OpenAPI refs (#/components/schemas/X) to the JSON Schema form expected by resolve_ref().
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                node[key] = value.replace("#/components/schemas/", "#/definitions/")
            else:
                rewrite_openapi_refs(value)
    elif isinstance(node, list):
        for item in node:
            rewrite_openapi_refs(item)


def rewrite_properties(
    node: JSONValue,
    *,
    rename: Mapping[str, str] | None = None,
    schemas: Mapping[str, JSONObject] | None = None,
) -> None:
    rename = rename or {}
    schemas = schemas or {}
    if isinstance(node, dict):
        if isinstance(props := node.get("properties"), dict):
            node["properties"] = {
                (name := rename.get(key, key)): schemas.get(name, value)
                for key, value in props.items()
            }
        for value in node.values():
            rewrite_properties(value, rename=rename, schemas=schemas)
    elif isinstance(node, list):
        for item in node:
            rewrite_properties(item, rename=rename, schemas=schemas)
