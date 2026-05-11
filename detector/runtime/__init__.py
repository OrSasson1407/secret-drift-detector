from abc import ABC, abstractmethod

class BaseProber(ABC):
    @abstractmethod
    async def probe(self) -> dict[str, str]:
        '''
        Returns a dictionary of environment variables (key-value pairs)
        found in the live runtime process.
        '''
        pass
