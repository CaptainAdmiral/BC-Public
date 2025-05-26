from dataclasses import dataclass
from typing import cast

class DialogueException(Exception):
    '''Exception with execution of dialogue'''
    ...

@dataclass
class DialogueResult[R]:
    exception: Exception | None
    success: bool
    result: R | None = None

    def __bool__(self):
        if not self.success:
            return False
        return bool(self.result)
    
    def assumed_result(self) -> R:
        '''Gets the result assuming the dialogue was successful. (Casts out the None from the result type union)'''
        return cast(R, self.result)