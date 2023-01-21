package messages;

public class SOCKS5Answer {
    public static final int VERByteNum = 0;
    public static final int VERSize = 1;
    public static final int REPByteNum = 1;
    public static final int REPSize = 1;
    public static final int RSVByteNum = 2;
    public static final int RSVSize = 1;
    public static final int ATYPByteNum = 3;
    public static final int ATYPSize = 1;
    public static final int BNDV4ByteNum = 4;
    public static final int BNDV4Size = 4;
    public static final int PORTV4ByteNum = 8;
    public static final int PORTV4Size = 2;

    public static final Byte REPsucceeded = 0;
    public static final Byte REPfail = 1;
    public static final Byte REPhostunreachable = 4;
    public static final Byte REPbadatyp = 8;
    public static final Byte ATYPV4 = 1;

    public Byte ver = 5;
    public Byte rep;
    public Byte rsv = 0;
    public Byte atyp;
    public byte[] bndAddressV4;
    public int port = 0;

    public SOCKS5Answer setVer(Byte ver) {
        this.ver = ver;
        return this;
    }

    public SOCKS5Answer setRep(Byte rep) {
        this.rep = rep;
        return this;
    }

    public SOCKS5Answer setRsv(Byte rsv) {
        this.rsv = rsv;
        return this;
    }

    public SOCKS5Answer setAtyp(Byte atyp) {
        this.atyp = atyp;
        return this;
    }

    public SOCKS5Answer setBndAddressV4(byte[] bndAddressV4) {
        this.bndAddressV4 = bndAddressV4;
        return this;
    }

    public SOCKS5Answer setPort(int port) {
        this.port = port;
        return this;
    }

    public byte[] toByteArray(){
        byte[] arr = new byte[VERSize+REPSize+RSVSize+ATYPSize+BNDV4Size+PORTV4Size];
        arr[VERByteNum] = ver;
        arr[REPByteNum] = rep;
        arr[RSVByteNum] = rsv;
        arr[ATYPByteNum] = atyp;
        System.arraycopy(bndAddressV4, 0, arr, BNDV4ByteNum, BNDV4Size);
        arr[PORTV4ByteNum] = (byte)((port >> Byte.SIZE) % (1 << Byte.SIZE));
        if ((port % (1 << Byte.SIZE)) > 128){
            arr[PORTV4ByteNum] = (byte) ((port >> Byte.SIZE) % (1 << Byte.SIZE) - 256);
        }
        else {
            arr[PORTV4ByteNum] = (byte) ((port >> Byte.SIZE) % (1 << Byte.SIZE));
        }
        if ((port % (1 << Byte.SIZE)) > 128){
            arr[PORTV4ByteNum+1] = (byte) (port % (1 << Byte.SIZE) - 256);
        }
        else {
            arr[PORTV4ByteNum+1] = (byte) (port % (1 << Byte.SIZE));
        }

        return arr;
    }
}
