import messages.SOCKS5Answer
import messages.SOCKS5Request
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.*
import java.nio.channels.spi.SelectorProvider


const val BUFFER_SIZE = 2048
const val SOCKS_VERSION = 5

enum class ATYP(val Byte: Byte) {
    V4(1), DOMAIN_NAME(3), V6(4)
}

class SOCKS5Proxy(port: Int) {
    private val serverSocketChannel: ServerSocketChannel = ServerSocketChannel.open()
    private val selector = SelectorProvider.provider().openSelector()
    private val serverAddress = ByteArray(4)

    init {
        serverSocketChannel.configureBlocking(false)
        serverSocketChannel.socket().bind(InetSocketAddress(port))
        serverSocketChannel.register(selector, serverSocketChannel.validOps())
        serverAddress[0] = 192.toByte()
        serverAddress[1] = 168.toByte()
        serverAddress[2] = 0.toByte()
        serverAddress[3] = 109.toByte()
    }

    internal class Attachment {

        /**
         * Буфер для чтения, в момент проксирования становится буфером для
         * записи для ключа хранимого в peer
         */
        var inBuf: ByteBuffer = ByteBuffer.allocate(BUFFER_SIZE)

        /**
         * Буфер для записи, в момент проксирования равен буферу для чтения для
         * ключа хранимого в peer
         */
        var outBuf: ByteBuffer = ByteBuffer.allocate(BUFFER_SIZE)

        /**
         * Куда проксируем
         */
        var peer: SelectionKey? = null

        //Произошел ли обмен методами аутентификации
        var greetingFinished: Boolean = false

        //Используется ли этот ключ для проксирования
        var isProxy: Boolean = false

        //Этап проксирования начат
        var isConnectionFinised = false


    }

    //Функция с главным циклом
    fun start() {
        while (selector.select() > -1) {
            for (key: SelectionKey in selector.selectedKeys()) {
                try {
                    if (key.isAcceptable) {
                        acceptKey(key)
                    } else if (key.isConnectable and (key.interestOps() and SelectionKey.OP_CONNECT > 0)) {
                        connect(key)
                    } else if (key.isWritable and (key.interestOps() and SelectionKey.OP_WRITE > 0)) {
                        write(key)
                    } else if (key.isReadable and (key.interestOps() and SelectionKey.OP_READ > 0)) {
                        read(key)

                    }

                } catch (_: CancelledKeyException) {
                } catch (e: java.lang.Exception) {
                    println(key.hashCode().toString() + e.stackTraceToString())
                    key.cancel()
                }
            }
        }
    }

    //Принимает новое соединение
    private fun acceptKey(key: SelectionKey) {
        val newChannel = (key.channel() as ServerSocketChannel).accept()
        if (newChannel != null) {
            newChannel.configureBlocking(false)
            val newKey = newChannel.register(key.selector(), SelectionKey.OP_READ)
            val attachment = Attachment()
            newKey.attach(attachment)
        }
    }

    //Функция, завершающая подключение с целевыми хостами и переводящая каналы в режим проксирования
    @Throws(
        IOException::class,
        NoConnectionPendingException::class
    )
    private fun connect(key: SelectionKey) {
        val channel = key.channel() as SocketChannel
        var channelAlive = true
        // Завершаем соединение
        val answer = SOCKS5Answer()
            .setRep(SOCKS5Answer.REPsucceeded)
            .setAtyp(SOCKS5Answer.ATYPV4)
            .setBndAddressV4(serverAddress)
        try {
            if (!channel.finishConnect()) {
                return
            }
        } catch (e: Exception) {
            channelAlive = false
            close(key)
        }


        val attachment = key.attachment() as Attachment
        val client = attachment.peer
        val clientAttachment = (client!!.attachment() as Attachment)

        if (channelAlive) {
            answer.setPort(channel.socket().localPort)
            key.interestOps(0)
            clientAttachment.peer = key
            clientAttachment.isProxy = true
            clientAttachment.isConnectionFinised = true
            attachment.isProxy = true
            attachment.isConnectionFinised = true
            attachment.inBuf = clientAttachment.outBuf
            attachment.outBuf = clientAttachment.inBuf
            attachment.outBuf.clear()
        } else {
            answer.setRep(SOCKS5Answer.REPhostunreachable)
        }

        clientAttachment.outBuf.clear()
        clientAttachment.outBuf.put(answer.toByteArray())
        clientAttachment.outBuf.flip()
        client.interestOpsOr(SelectionKey.OP_WRITE)
    }

    @Throws(IOException::class, ClosedChannelException::class)
    private fun read(key: SelectionKey) {
        val channel = key.channel() as SocketChannel
        val attachment = key.attachment() as Attachment
        val num: Int
        try {
            num = channel.read(attachment.inBuf)
        } catch (e: Exception) {
            close(key)
            return
        }

        if (num < 0) {
            close(key)
        } else if (num == 0) {
            return
        }

        if (!attachment.isProxy) {
            if (!attachment.greetingFinished) {
                greet(key)
            } else {
                acceptRequest(key, attachment)
            }
        } else if (attachment.isConnectionFinised) {
            // если мы проксируем, то добавляем ко второму концу интерес
            // записать
            attachment.peer!!.interestOpsOr(SelectionKey.OP_WRITE)
            // а у первого убираем интерес прочитать, т.к пока не записали
            // текущие данные, читать ничего не будем
            if (key.isValid) {
                key.interestOps(key.interestOps() xor SelectionKey.OP_READ)
            } else {
                close(attachment.peer!!)
            }
            // готовим буфер для записи
            attachment.inBuf.flip()
        }
    }

    //Выполняет обмен методами аутентификации
    private fun greet(key: SelectionKey) {
        val attachment = key.attachment() as Attachment
        val ar: ByteArray = attachment.inBuf.array()
        if (attachment.inBuf.position() > 1) {
            //printByteArr(attachment.inBuf.array())
            if (ar[0].compareTo(SOCKS_VERSION) != 0) {
                attachment.outBuf.put(5)
                attachment.outBuf.put(0)
                key.interestOps(SelectionKey.OP_WRITE)
                return
            }
            if (attachment.inBuf.position() != (2 + ar[1])) {
                return
            }
            val methodsSet = HashSet<Byte>()
            for (b in ar.slice(2 until ar.size)) {
                methodsSet.add(b)
            }
            if (methodsSet.contains(0)) {
                attachment.outBuf.put(SOCKS_VERSION.toByte())
                attachment.outBuf.put(0)
                attachment.outBuf.flip()
                key.interestOpsOr(SelectionKey.OP_WRITE)
                attachment.inBuf.clear()
                attachment.greetingFinished = true
                //println("Должен отправить")
            } else {
                close(key)
            }
        }
    }

    //принимает запрос от клиента
    private fun acceptRequest(key: SelectionKey, attachment: Attachment) {
        val ar: ByteArray = attachment.inBuf.array()
        if (attachment.inBuf.position() >= SOCKS5Request.PORTByteNum + SOCKS5Request.PORTSize) {
            val port: Int
            val ipString: String
            val addr: InetAddress
            if (ar[SOCKS5Request.ATYPByteNum] == ATYP.V4.Byte) {
                port = ByteConverter.bytesToPort(ar[SOCKS5Request.PORTByteNum], ar[SOCKS5Request.PORTByteNum + 1])
                ipString =
                    ByteConverter.bytesToIP(ar.sliceArray(SOCKS5Request.DSTV4ByteNum until SOCKS5Request.DSTV4ByteNum + SOCKS5Request.DSTV4Size))
                addr = InetAddress.getByName(ipString)
            } else if (ar[SOCKS5Request.ATYPByteNum] == ATYP.DOMAIN_NAME.Byte) {
                val domainNameSize = ByteConverter.toPositiveInt(ar[SOCKS5Request.DSTDOMENNAMESIZEByteNum])
                if (attachment.inBuf.position() >= SOCKS5Request.DSTDOMENNAMESIZEByteNum + 1 + domainNameSize + SOCKS5Request.PORTSize) {
                    val domain =
                        String(ar.sliceArray(SOCKS5Request.DSTDOMENNAMEByteNum until SOCKS5Request.DSTDOMENNAMEByteNum + domainNameSize))
                    try {
                        addr = InetAddress.getByName(domain)
                    } catch (e: Exception) {
                        val answer = SOCKS5Answer()
                            .setRep(SOCKS5Answer.REPhostunreachable)
                            .setAtyp(SOCKS5Answer.ATYPV4)
                            .setBndAddressV4(serverAddress)
                        attachment.outBuf.put(answer.toByteArray())
                        attachment.outBuf.flip()
                        key.interestOpsOr(SelectionKey.OP_WRITE)
                        return
                    }
                    val portdest = SOCKS5Request.DSTDOMENNAMESIZEByteNum + 1 + domainNameSize
                    port = ByteConverter.bytesToPort(ar[portdest], ar[portdest + 1])
                } else {
                    return
                }

            } else {
                //Говорим, что не поддерживаем данный тип адреса
                val answer = SOCKS5Answer()
                    .setRep(SOCKS5Answer.REPbadatyp)
                    .setAtyp(SOCKS5Answer.ATYPV4)
                    .setBndAddressV4(serverAddress)
                attachment.outBuf.put(answer.toByteArray())
                attachment.outBuf.flip()
                key.interestOpsOr(SelectionKey.OP_WRITE)
                return

            }
            //Если я здесь, то с запросом все в порядке и пробуем установить соединение
            val peer = SocketChannel.open()
            peer.configureBlocking(false)
            peer.connect(InetSocketAddress(addr, port))
            val peerKey = peer.register(key.selector(), SelectionKey.OP_CONNECT)
            val newAttachment = Attachment()
            newAttachment.isProxy = true
            newAttachment.peer = key
            peerKey.attach(newAttachment)
        }
    }


    @Throws(IOException::class)
    private fun write(key: SelectionKey) {
        val attachment = key.attachment() as Attachment
        val channel = key.channel() as SocketChannel
        val num = channel.write(attachment.outBuf)
        if (num == -1) {
            close(key)
        } else if (attachment.outBuf.remaining() == 0) {
            key.interestOps(key.interestOps() xor SelectionKey.OP_WRITE)
            attachment.outBuf.clear()
            if (attachment.isProxy and attachment.isConnectionFinised) {
                if (attachment.peer == null) {
                    // Дописали что было в буфере и закрываемся
                    close(key)
                } else {
                    attachment.peer!!.interestOpsOr(SelectionKey.OP_READ)
                }

            }
        }

    }

    @Throws(IOException::class)
    private fun close(key: SelectionKey) {
        key.cancel()
        key.channel().close()
        val attachment = key.attachment() as Attachment
        if (attachment.isProxy and attachment.isConnectionFinised) {
            val peer = (key.attachment() as Attachment).peer
            if (peer != null) {
                val peersAttachment = peer.attachment() as Attachment
                peersAttachment.peer = null
                peersAttachment.isProxy = false
                peersAttachment.isConnectionFinised = false
            }
        }


    }
}