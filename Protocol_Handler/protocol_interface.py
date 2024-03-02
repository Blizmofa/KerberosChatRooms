from abc import ABC, abstractmethod
from typing import Union, Optional


class ProtocolHandlerInterfaces(ABC):
    """Auxiliary interface to improve Protocol Handler performances."""

    @abstractmethod
    def pack_request(self, code: int, data: dict, formatter: dict) -> bytes:
        """Main pack packet method to be override."""
        raise NotImplementedError(f"{self.pack_request.__name__} must be implemented.")

    @abstractmethod
    def unpack_request(self, code: int, received_packet: bytes, formatter: dict, deserialize: Optional[bool] = False) -> Union[dict, tuple]:
        """Main unpack packet method to be override."""
        raise NotImplementedError(f"{self.unpack_request.__name__} must be implemented.")