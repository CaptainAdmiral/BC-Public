from typing import Callable

def get_referenced[T](f: Callable, Type: type[T]) -> list[T]:
    '''Return all nonlocal variables of Type referenced by f'''
    
    closure_vars = iter(())
    if f.__closure__:
        closure_vars = (cell.cell_contents for cell in f.__closure__)

    global_vars = (globals()[name] for name in f.__code__.co_names if name in globals())
    
    vars = [*closure_vars, *global_vars]

    return [var for var in vars if isinstance(var, Type)]