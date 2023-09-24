from rest_framework.throttling import (
    AnonRateThrottle,
    BaseThrottle,
    ScopedRateThrottle,
    SimpleRateThrottle,
    UserRateThrottle,
)


class AnonUserRateThrottle(AnonRateThrottle):
    rate = "1/min"
