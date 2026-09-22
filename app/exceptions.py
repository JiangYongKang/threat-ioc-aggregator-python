"""服务内部使用的异常定义（用于区分失败原因）。"""

from __future__ import annotations


class IOCServiceError(Exception):
    """所有服务异常的基类。"""

    code = "service_error"


class BatchRejected(IOCServiceError):
    """非法批次：整批拒绝，不得产生任何写入。"""

    code = "batch_rejected"

    def __init__(self, reason: str, detail: str | None = None) -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


class EntryRejected(IOCServiceError):
    """单条情报无法归一（拒绝入库）。"""

    code = "entry_rejected"

    def __init__(self, reason: str, detail: str | None = None) -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)
