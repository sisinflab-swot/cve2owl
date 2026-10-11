from collections.abc import Callable, Hashable, Iterable, Iterator


def unique[T](items: Iterable[T], key: Callable[[T], Hashable] | None = None) -> Iterator[T]:
    seen: set[Hashable] = set()
    for item in items:
        k = item if key is None else key(item)
        if k not in seen:
            seen.add(k)
            yield item


def not_none[T](items: Iterable[T | None]) -> Iterator[T]:
    return (item for item in items if item is not None)


def or_none[**P, R](func: Callable[P, R], *exceptions: type[Exception]) -> Callable[P, R | None]:
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R | None:
        try:
            return func(*args, **kwargs)
        except exceptions:
            return None

    return wrapper
