package constants

const (
	RATE_LIMIT_INTERVAL                    = 1000 // 1s
	MAX_TOKENS                        int8 = 10   // Every user has 10 tokens alotted every sec
	TOKEN_CONSUMPTION_PER_REQUEST          = 1
	EXPONENTIAL_BACKOFF_RATE_LIMIT_MS      = 3000    // Base backoff:(3 second)
	MAX_RETRY_AFTER_MS                     = 120_000 // Max backoff: 120 seconds
	MAX_CONNECT_TOKENS                     = 20      // IP block limit if 20 invalid requests are sent just block the ip could cause issues for others using the same home network
)