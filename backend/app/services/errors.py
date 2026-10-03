"""Domain errors raised by services and mapped to HTTP responses in app.main."""


class NotFoundError(Exception):
    pass


class ConflictError(Exception):
    pass


class UnprocessableError(Exception):
    pass
