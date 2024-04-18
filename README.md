# OAuthUtility - Generate OAuth 1.0 headers with ease. 

OAuthUtility is a module that generates OAuth 1.0 signatures and headers for you. OAuthUtility offers four signature methods including HMAC-SHA1, SHA256, SHA512, and PLAINTEXT. 
For more information on usage, you can view the [Wiki](https://github.com/benpinpop/OAuthUtility/wiki).

Dependencies/Credit:
OAuthUtility uses [Egor Skriptunoff's SHA module](https://github.com/Egor-Skriptunoff/pure_lua_SHA) and [metatablecat's](https://github.com/metatablecat) Base64 module. 

## Performance and Benchmarks

Header generation per specific signature type using randomly generated strings between the length of 10-15. (10,000 iterations)
```
Benchmark results for: HMAC-SHA1
Total time: 5.174962999999934 seconds
Average time per iteration: 0.0005174962999999934 seconds
50th percentile: 0.00045339999996940605 seconds
95th percentile: 0.00036649999992732774 seconds
99th percentile: 0.0003627000000960834 seconds

Benchmark results for: HMAC-SHA256
Total time: 8.458412899999985 seconds
Average time per iteration: 0.0008458412899999985 seconds
50th percentile: 0.0007770000001983135 seconds
95th percentile: 0.0006315000000540749 seconds
99th percentile: 0.0006270999997468607 seconds

Benchmark results for: HMAC-SHA512
Total time: 16.62855579999996 seconds
Average time per iteration: 0.001662855579999996 seconds
50th percentile: 0.0015470000003006135 seconds
95th percentile: 0.0012585000004037283 seconds
99th percentile: 0.0012515000003077148 seconds

Benchmark results for: PLAINTEXT
Total time: 0.889474699999937 seconds
Average time per iteration: 0.0000889474699999937 seconds
50th percentile: 0.00006290000010267249 seconds
95th percentile: 0.00005139999984749011 seconds
99th percentile: 0.000050600000122358324 seconds
```
