class ByteConverter {
    public static String bytesToIP(byte [] ar){
        var string = "";
        string += toPositiveInt(ar[0]);
        string += ".";
        string += toPositiveInt(ar[1]);
        string += ".";
        string += toPositiveInt(ar[2]);
        string += ".";
        string += toPositiveInt(ar[3]);
        return string;
    }
    public static int bytesToPort(Byte b1, Byte b2){
        int i1 = toPositiveInt(b1);
        int  i2 = toPositiveInt(b2);
        return (i1 << Byte.SIZE) + i2;
    }
    public static int toPositiveInt(Byte b){
        int integer = 0;
        var m = 1;
        for (int i = 0; i < 8; i++){
            integer +=  ((b & (1 << i)) >> i) * m;
            m*=2;
        }
        return integer;
    }
}