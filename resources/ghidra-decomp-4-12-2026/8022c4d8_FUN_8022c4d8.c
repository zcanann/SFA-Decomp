// Function: FUN_8022c4d8
// Entry: 8022c4d8
// Size: 700 bytes

void FUN_8022c4d8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10)

{
  double dVar1;
  int iVar2;
  
  iVar2 = param_10 + 0xc0;
  (**(code **)(*DAT_803dd728 + 0x10))((double)FLOAT_803dc074,param_9,iVar2);
  (**(code **)(*DAT_803dd728 + 0x14))(param_9,iVar2);
  (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,param_9,iVar2);
  dVar1 = DOUBLE_803e7b80;
  if ((*(char *)(param_10 + 0x338) == '\0') || (*(char *)(param_10 + 0x478) == '\x04')) {
    if (*(byte *)(param_10 + 800) != 0) {
      if (*(char *)(param_10 + 0x478) == '\x04') {
        *(undefined *)(param_10 + 0x478) = 5;
        *(float *)(param_10 + 0x46c) = FLOAT_803e7bbc;
        *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) | 0x4000;
        FUN_8009adfc((double)FLOAT_803e7bc0,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,1,0,1,1,0,1,0);
      }
      else {
        if (((*(byte *)(param_10 + 800) & 1) == 0) || (*(char *)(param_10 + 0x178) != '\b')) {
          *(char *)(param_10 + 0x468) = *(char *)(param_10 + 0x468) + -1;
        }
        else {
          *(undefined *)(param_10 + 0x468) = 0;
        }
        FUN_80014acc((double)FLOAT_803e7bc4);
        if (*(char *)(param_10 + 0x468) < '\x01') {
          FUN_8022f80c(*(int *)(param_10 + 0x10),'\0','\0');
          if (*(char *)(param_9 + 0xac) == '&') {
            FUN_800201ac(0xe74,1);
          }
          else {
            *(undefined *)(param_10 + 0x478) = 4;
          }
          *(float *)(param_10 + 0x46c) = FLOAT_803e7bc8;
          FUN_8000bb38(param_9,0x380);
          FUN_8000a538((int *)0xd6,1);
        }
        else if (*(char *)(*(int *)(param_9 + 0xb8) + 0x468) < '\x04') {
          FUN_8000da78(param_9,0x37f);
        }
        FUN_8000bb38(param_9,0x2a0);
        *(byte *)(param_10 + 0x339) = *(byte *)(param_10 + 0x339) & 0x7f | 0x80;
        FUN_8002ad08(param_9,0x4b,200,0,0,1);
        *(float *)(param_10 + 0x328) = FLOAT_803e7bcc;
        *(undefined *)(param_10 + 0x338) = 1;
        *(undefined2 *)(param_10 + 0x33a) = 0;
        *(undefined2 *)(param_10 + 0x33c) = 0;
        *(undefined4 *)(param_10 + 0x32c) = *(undefined4 *)(param_10 + 0x260);
        *(undefined4 *)(param_10 + 0x330) = *(undefined4 *)(param_10 + 0x264);
        FUN_8000faf8();
        FUN_8000e69c((double)FLOAT_803e7bd0);
      }
    }
  }
  else {
    *(short *)(param_10 + 0x33a) =
         (short)(int)(FLOAT_803e7bd4 * FLOAT_803dc074 +
                     (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_10 + 0x33a)) -
                            DOUBLE_803e7b80));
    *(short *)(param_10 + 0x33c) =
         (short)(int)(FLOAT_803e7bd8 * FLOAT_803dc074 +
                     (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_10 + 0x33c)) -
                            dVar1));
  }
  return;
}

