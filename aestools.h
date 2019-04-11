//#ifndef SRC_UTILS_TAESCLASS_H
#define SRC_UTILS_TAESCLASS_H

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "aes.h"


class AesTools
{
public:
    AesTools();
    ~AesTools();
  void InitializePrivateKey(DWORD KeySize,UCHAR *KeyBytes); //AES 密钥初始化
    DWORD OnAesEncrypt(LPVOID InBuffer,DWORD InLength,LPVOID OutBuffer);            //AES 加密数据
    DWORD OnAesUncrypt(LPVOID InBuffer,DWORD InLength,LPVOID OutBuffer);            //AES 解密数据
    unsigned int extraBytes;
    unsigned int ciphertextLength;


    void FileEncryptor(QString inFileName,QString outFileName);//AES 加密文件
    void FileDecryptor(QString inFileName,QString outFileName);//AES 解密文件
private:
    Aes * m_lpAes;

    QByteArray OpenFile(QString fileName); //打开指定文件
    void WriteFile(QString fileName,QByteArray data); //将内容data写入到指定的文件内
};
