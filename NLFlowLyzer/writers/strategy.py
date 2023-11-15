#!/usr/bin/env python3

from abc import ABC, abstractmethod

class Strategy(ABC):
    @abstractmethod
    def write(self, file_address: str, data: list) -> None:
        pass

