# CYBER PATH FINDER

TODO
- Parallelize
    - Send 8, 16, 32 in goroutines
    - When receive, LookupAddr of sender in goroutine
    - If receive echo, cancel all outstanding requests with larger TTL

- Should take names or IPs

- Timeout problems?
    - Try with a longer timeout?
    - Try with tcp/udp?
