// Function: FUN_8022c794
// Entry: 8022c794
// Size: 572 bytes

void FUN_8022c794(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10)

{
  char cVar1;
  float fVar2;
  byte bVar5;
  int iVar3;
  undefined4 uVar4;
  undefined8 uVar6;
  int local_18;
  uint local_14 [3];
  
  bVar5 = FUN_8002acfc(param_9);
  if (bVar5 == 0) {
    iVar3 = FUN_80036974(param_9,&local_18,(int *)0x0,local_14);
    if ((iVar3 != 0) && (local_14[0] != 0)) {
      if (*(char *)(param_10 + 0x478) == '\x04') {
        *(undefined *)(param_10 + 0x478) = 5;
        *(float *)(param_10 + 0x46c) = FLOAT_803e7bbc;
        *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) | 0x4000;
        FUN_8009adfc((double)FLOAT_803e7bc0,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,1,0,1,1,0,1,0);
      }
      else {
        if ((*(short *)(local_18 + 0x46) == 0x6ae) && (*(char *)(param_10 + 0x478) == '\x01')) {
          FUN_8000bb38(param_9,0x2c0);
          return;
        }
        FUN_80014acc((double)FLOAT_803e7bc4);
        *(char *)(param_10 + 0x468) = *(char *)(param_10 + 0x468) - (char)local_14[0];
        FUN_8000bb38(param_9,0x2ac);
        *(byte *)(param_10 + 0x339) = *(byte *)(param_10 + 0x339) & 0x7f | 0x80;
        FUN_8002ad08(param_9,0x4b,200,0,0,1);
        *(float *)(param_10 + 0x328) = FLOAT_803e7bcc;
        *(undefined *)(param_10 + 0x338) = 1;
        *(undefined2 *)(param_10 + 0x33a) = 0;
        *(undefined2 *)(param_10 + 0x33c) = 0;
        fVar2 = FLOAT_803e7b64;
        *(float *)(param_10 + 0x32c) = FLOAT_803e7b64;
        *(float *)(param_10 + 0x330) = fVar2;
        FUN_8000faf8();
        FUN_8000e69c((double)FLOAT_803e7bc4);
      }
    }
    cVar1 = *(char *)(param_10 + 0x478);
    if ((((cVar1 == '\x04') || (cVar1 == '\x05')) || (cVar1 == '\x06')) ||
       ('\0' < *(char *)(param_10 + 0x468))) {
      if (*(char *)(*(int *)(param_9 + 0xb8) + 0x468) < '\x04') {
        FUN_8000da78(param_9,0x37f);
      }
    }
    else {
      FUN_8022f80c(*(int *)(param_10 + 0x10),'\0','\0');
      if (*(char *)(param_9 + 0xac) == '&') {
        FUN_800201ac(0xe74,1);
      }
      *(undefined *)(param_10 + 0x478) = 4;
      *(float *)(param_10 + 0x46c) = FLOAT_803e7bc8;
      uVar6 = FUN_8000bb38(param_9,0x380);
      FUN_8000a538((int *)0xd6,1);
      FUN_80043604(0,0,1);
      FUN_80043070(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x29);
      uVar4 = FUN_8004832c(0x29);
      FUN_80043658(uVar4,0);
    }
  }
  return;
}

