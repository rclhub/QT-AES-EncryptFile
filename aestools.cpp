#include "aestools.h"
#include <QDebug>
#include "qstring.h"
#include <QFile>


AesTools::AesTools()
{
    m_lpAes=NULL;
    InitializePrivateKey(16,(unsigned char*)"\x79\x76\x68\x6B\x77\x66\x6E\x68\x72\x65\x73\x63\x6C\x6B\x70\x6E");
}

AesTools::~AesTools()
{
    if (m_lpAes!=NULL)
    {
        delete m_lpAes;
    }
}
//------------------------------------------------------------------------------------------------------------
// 编写人员：wfnhddd
//
// 函数名称：InitializeAes
//
// 函数描述：初始化AES 密钥，密钥用于加密解密
//
// 调用参数：详细说明参考 MSDN 中的相关描述或相关的开发文档
//
// 返回数值：无
//
// 最近修改：2009 年 08 月 07 日
//------------------------------------------------------------------------------------------------------------


VOID AesTools::InitializePrivateKey(DWORD KeySize,UCHAR *KeyBytes)
{
    if (m_lpAes)
    {
        delete m_lpAes;
        m_lpAes=NULL;
    }
    m_lpAes=new Aes(KeySize,KeyBytes);

}

//------------------------------------------------------------------------------------------------------------
// 编写人员：wfnhddd
//
// 函数名称：OnAesEncrypt
//
// 函数描述：用AES加密算法加密数据
//
// 调用参数：详细说明参考 MSDN 中的相关描述或相关的开发文档
//
// 返回数值：加密后的数据大小 ，错误返回值 0
//
// 最近修改：2009 年 08 月 07 日
//------------------------------------------------------------------------------------------------------------

DWORD AesTools::OnAesEncrypt(LPVOID InBuffer,DWORD InLength,LPVOID OutBuffer)
{
    //DWORD占4个字节
    DWORD OutLength=0,ExtraBytes = 0;
    if (m_lpAes==NULL||OutBuffer==NULL)
    {
        return 0;
    }

    //InBuffer是一个char类型的数组，lpCurInBuff指针指向的是InBuffer char数组的第一个元素的地址
    UCHAR *lpCurInBuff=(UCHAR *)InBuffer;
    //加密后的数据往OutBuffer中写入时，从第16个字节开始写。前面空出16个字节，用于存放密文大小和额外加密的字节个数，只用到8个字节，但为了保证字节总数是16的倍数，故预留了16个字节
    UCHAR *lpCurOutBuff=(UCHAR *)OutBuffer+16;
    long blocknum=InLength/16;
    long leftnum=InLength%16;
    for(long i=0;i<blocknum;i++)
    {
        //加密时，传入的数组必须时16个字节的
        m_lpAes->Cipher(lpCurInBuff,lpCurOutBuff);
        //每次加密16个字节，循环直至所有字节均被加密
        lpCurInBuff+=16;
        lpCurOutBuff+=16;
        OutLength+=16;
    }
    //当传入的密文的字节总数不是16的倍数时，会多余出leftnum 个字节。
    //此时，需要添加16-leftnum 个字节到mingwen中。则加密得到的密文，会多出16-leftnum 个字节。
    //这16-leftnum 个字节并不是mingwen里存在的
    if(leftnum)
    {
        UCHAR inbuff[16];
        memset(inbuff,'X',16);
        //经过上面的for循环，此时lpCurInBuff指针指向InBuffer数组的sizeof(InBuffer)-leftnum 位置处
        memcpy(inbuff,lpCurInBuff,leftnum);
        //此次解密，实际上是多加密了16-leftnum 个字节
        m_lpAes->Cipher(inbuff,lpCurOutBuff);
        lpCurOutBuff+=16;
        OutLength+=16;
    }
    UCHAR *bytesSize=(UCHAR *)OutBuffer;
    UCHAR *extraBytesSize = (UCHAR *)(OutBuffer+4);

    //多加密的字节个数
    ExtraBytes = (16-leftnum)%16;
    //将OutLength的地址复制给bytesSize的前4个字节。即将加密后的密文大小存放在miwen的前四个字节中
    memcpy(bytesSize,&OutLength,4);
    //将多加密的字节个数存放在第4-8个字节中
    memcpy(extraBytesSize,&ExtraBytes,4);

    //返回的OutLength只包括密文长度，不包括outBuffer中预留用来存放outBuffer字节个数和额外多加密的字节个数的16字节。
    //即OutLength = sizeof(OutBuffer)-16
    return OutLength;

}


//------------------------------------------------------------------------------------------------------------
// 编写人员：wfnhddd
//
// 函数名称：OnAesUncrypt
//
// 函数描述：用AES加密算法解密数据
//
// 调用参数：详细说明参考 MSDN 中的相关描述或相关的开发文档
//
// 返回数值：解密后的数据大小 ，错误返回值 0
//
// 最近修改：2009 年 08 月 07 日
//------------------------------------------------------------------------------------------------------------
DWORD AesTools::OnAesUncrypt(LPVOID InBuffer,DWORD InLength,LPVOID OutBuffer)
{
    //传入的InLength大小是加密时返回的OutLength+16，即outBuffer的大小
    DWORD OutLength=0,ExtraBytes=0;
    if (m_lpAes==NULL||OutBuffer==NULL)
    {
        return 0;
    }
    //密文是从第16个字节开始的，故解密时，前16个字节忽略，直接从第16个字节开始解密
    UCHAR *lpCurInBuff=(UCHAR *)InBuffer+16;
    UCHAR *lpCurOutBuff=(UCHAR *)OutBuffer;
    long blocknum=InLength/16;
    long leftnum=InLength%16;
    if(leftnum){//传入的密文大小必须是16的整数倍个字节
                return 0;
    }

    //每次解密16个字节，循环全部解出
    for(long i=0;i<blocknum;i++)
    {
        m_lpAes->InvCipher(lpCurInBuff,lpCurOutBuff);
        lpCurInBuff+=16;
        lpCurOutBuff+=16;
        OutLength+=16;
    }

    //ExtraBytesSize指针指向的是InBuffer的第四个字节处
    UCHAR* ExtraBytesSize =(UCHAR *) InBuffer+4;
    //将InBuffer的第4-8个字节中的内容复制给ExtraBytes。此时ExtraBytes代表的是加密是额外加密的字节数
    memcpy(&ExtraBytes,ExtraBytesSize,4);
    //将额外加密的那部分内容，即ExtraBytes个字节的内容置为0
    memset(lpCurOutBuff-ExtraBytes,0,ExtraBytes);
    return (OutLength);

}

//打开文件，将文件中的内容返回一个QbyteArray的数组
QByteArray AesTools::OpenFile(QString fileName){
    QFile file(fileName);
    file.open(( QIODevice::ReadWrite));
    QByteArray temp = file.read(file.bytesAvailable());
    file.close();
    return temp;
}

//将一个QbyteArray数组写入到指定文件中去。
//使用二进制数组进行文件的读写能够有效避免各种由于编码格式和类型转换造成的问题
void AesTools::WriteFile(QString fileName, QByteArray data){
    QFile file(fileName);
    file.open(( QIODevice::ReadWrite|QIODevice::Truncate));
    file.write(data);
    file.close();
    return ;
}

//加密
void AesTools::FileEncryptor(QString inFileName,QString outFileName) {

    QByteArray temp = OpenFile(inFileName);
    //qDebug()<<"temp:"<<temp;
    char mingwen[1024] ;
    //将temp字节数组中的所有数据复制给mingwen数组
    memcpy(mingwen,temp.data(),temp.size());
    //DWORD size = strlen(mingwen);
    //qDebug()<<"size:"<<size;
    char miwen[1024]={0};
    UCHAR key[1024] = "xyz";
    UCHAR *p = key;
    InitializePrivateKey(16, p); //进行初始化

    OnAesEncrypt((LPVOID)mingwen, strlen(mingwen), (LPVOID)miwen); //进行加密
    //qDebug()<<miwen;
    QByteArray miwenData;
    DWORD byteSize = 0;
    //将密文的前四个字符复制给bytesize的地址
    memcpy(&byteSize,miwen,4);
    //qDebug()<<"bytesize:"<<byteSize;
    miwenData.resize(byteSize+16);
    //将密文的前byteSize+16个字符复制给miwenDate
    memcpy(miwenData.data(),miwen,byteSize+16);

    WriteFile(outFileName,miwenData);

    return ;
}


void AesTools::FileDecryptor(QString inFileName,QString outFileName){

    QByteArray temp = OpenFile(inFileName);

    char miwen[1024]={0};
    char jiemi[1024]={0};
    //将temp字节数组中的所有数据复制给miwen char类型数组
    memcpy(miwen,temp.data(),temp.size());
    DWORD byteSize = 0;
    //miwen的大小存放在miwen的前四个字节中，将miwen大小赋值给byteSize
    memcpy(&byteSize,miwen,4);
    UCHAR key[1024] = "xyz";
    UCHAR *p = key;
    InitializePrivateKey(16, p); //进行初始化
    OnAesUncrypt((LPVOID)miwen, (DWORD)byteSize,(LPVOID)jiemi); //进行解密

    //解密结果写入文件中
    WriteFile(outFileName,jiemi);

    return ;
}
