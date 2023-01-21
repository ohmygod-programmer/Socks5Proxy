
fun main(args: Array<String>) {

    val port = 1080
    val socks5Proxy = SOCKS5Proxy(port)
    socks5Proxy.start()

}



