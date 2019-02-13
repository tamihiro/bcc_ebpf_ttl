About
-----

I wrote this as a little practice to see how to do what Cloudflare folks demonstrated in [this blog](https://blog.cloudflare.com/epbf_sockets_hop_distance/), using BPF Compiler Collection (BCC).

Example run:

    sudo python ebpf_ttl.py tcp4://google.com:80 tcp6://google.com:80
    >>>> Adding map entry:  tcp4://google.com:80
    >>>> Adding map entry:  tcp6://google.com:80
    TTL distatnce to tcp4://google.com:80 172.217.31.174 is 9 (ttl 119)
    TTL distatnce to tcp6://google.com:80 2404:6800:4004:80b::200e is 9 (ttl 119)
