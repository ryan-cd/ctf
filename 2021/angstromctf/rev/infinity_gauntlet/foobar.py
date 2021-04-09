def foo(x, y, result):
    if result is None:
        return (y + 1) ^ x ^ 1337
    elif x is None:
        return result ^ (y + 1) ^ 1337
    elif y is None:
        return (result ^ x ^ 1337) - 1

def bar(x, y, z, result):
    if result is None:
        return (z + 1) * y + x
    elif x is None:
        return result - (z + 1) * y
    elif y is None:
        return (result - x) // (z + 1)
    elif z is None:
        return (result - x) // y - 1
