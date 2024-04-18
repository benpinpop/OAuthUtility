# OAuthUtility - Generate OAuth 1.0 headers with ease. 

OAuthUtility is a module that generates OAuth 1.0 signatures and headers for you. OAuthUtility offers four signature methods including HMAC-SHA1, SHA256, SHA512, and PLAINTEXT. 
For more information on usage, you can view the [Wiki](https://github.com/benpinpop/OAuthUtility/wiki).

Dependencies/Credit:
OAuthUtility uses [Egor Skriptunoff's SHA module](https://github.com/Egor-Skriptunoff/pure_lua_SHA) and [metatablecat's](https://github.com/metatablecat) Base64 module. 

## Performance and Benchmarks

Header generation per specific signature type using randomly generated strings between the length of 10-15. 
```
Benchmark results for: HMAC-SHA1
Iterations: 10000
Total time: 3.5834829999998874 seconds
Average time per iteration: 0.00035834829999998875 seconds

Benchmark results for: HMAC-SHA256
Iterations: 10000
Total time: 3.8484964000003856 seconds
Average time per iteration: 0.0003848496400000386 seconds

Benchmark results for: HMAC-SHA512
Iterations: 10000
Total time: 7.464801699999953 seconds
Average time per iteration: 0.0007464801699999953 seconds

Benchmark results for: PLAINTEXT
Iterations: 10000
Total time: 0.33373429999983273 seconds
Average time per iteration: 0.00003337342999998327 seconds
```
