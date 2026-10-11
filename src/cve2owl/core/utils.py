from collections.abc import Callable, Hashable, Iterable, Iterator


def unique[T](items: Iterable[T], key: Callable[[T], Hashable] | None = None) -> Iterator[T]:
    seen: set[Hashable] = set()
    for item in items:
        k = item if key is None else key(item)
        if k not in seen:
            seen.add(k)
            yield item
