#include <QCoreApplication>
#include <aestools.h>
#include <qdebug.h>
#include <iostream>
#include <fstream>
#include <QFile>
#include <cmath>
#include <iomanip>
using namespace std;
int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    //创建对象
    AesTools *aes = new AesTools;
    //设置密钥，保证加密和解密的密钥一致
    UCHAR key[1024] = "xyz";
    UCHAR *p = key;
    DWORD keySize = strlen((char *)key);
    //进行密钥初始化
    aes->InitializePrivateKey(keySize, p);


    //文件的加密和解密。给定的是相对路径，也可以直接给绝对路径。
    aes->FileEncryptor("./project/test.txt","./project/test_encrypt.txt");
    aes->FileDecryptor("./project/test_encrypt.txt","./project/test_decrypt.txt");


    //字符数组的加密和解密
    //数组的大小可以自己设定，只要是16的倍数即可，而且要保证mingwen、miwen、jiemi的大小一致
    char mingwen[1024] ="hdgfgghgjf中国文字方式结构化kgkhytytrytryhgjdf";
    char miwen[1024]={0};
    char jiemi[1024]={0};
    //加密，返回值是密文的大小
    DWORD miwenLength = aes->OnAesEncrypt((LPVOID)mingwen, strlen(mingwen), (LPVOID)miwen);
    //解密
    QByteArray miwenData;
    DWORD byteSize = 0;
    memcpy(&byteSize,miwen,4);
    //byteSize即为存储的密文大小，满足byteSize=miwenLength。
    DWORD jiemiLength =aes->OnAesUncrypt((LPVOID)miwen, byteSize, (LPVOID)jiemi);


    /*
        字符数组和文件的加密解密上面代码已经完成，以下代码是为了能够看到密文的打印效果。
        1、直接打印"miwen"到控制台，无法看到密文
        2、使用 strlen(miwen) 方法也无法在控制台得到正确的密文大小
        3、皆是因为密文的前十六个字节中存放的是两个 int 类型的数，其包含有字符"\0"
    */
    DWORD size = strlen(mingwen);
    qDebug()<<"size:"<<size;
    qDebug()<<"miwenLength:"<<miwenLength;
    qDebug()<<"miwen:"<<miwen;
    //打印密文到控制台看不到密文，这是因为密文的前十六个字节存放的是密文的字节个数，其包含有字符"\0"，qDebug遇到该字符自动结束打印
    qDebug()<<"miwen.size:"<<strlen(miwen);
    //打印结果为1，因为strlen()方法统计字符个数时，遇到字符"\0"就结束。
    qDebug()<<"byteSize:"<<byteSize;
    miwenData.resize(byteSize+16);
    //打印密文的第16个字节以后的内容
    memcpy(miwenData.data(),miwen+16,byteSize);
    qDebug()<<"miwenData:"<<miwenData;

    qDebug()<<"jiemi:"<<jiemi;
    qDebug()<<"jiemiLength:"<<jiemiLength;


    //对象释放
    free(aes);
    aes = 0;

    return 0;

}


