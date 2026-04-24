// Function: FUN_8022c0d0
// Entry: 8022c0d0
// Size: 572 bytes

void FUN_8022c0d0(int param_1,int param_2)

{
  char cVar1;
  float fVar2;
  int iVar3;
  undefined4 uVar4;
  int local_18;
  int local_14 [3];
  
  iVar3 = FUN_8002ac24();
  if (iVar3 == 0) {
    iVar3 = FUN_8003687c(param_1,&local_18,0,local_14);
    if ((iVar3 != 0) && (local_14[0] != 0)) {
      if (*(char *)(param_2 + 0x478) == '\x04') {
        *(undefined *)(param_2 + 0x478) = 5;
        *(float *)(param_2 + 0x46c) = FLOAT_803e6f24;
        *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
        FUN_8009ab70((double)FLOAT_803e6f28,param_1,1,0,1,1,0,1,0);
      }
      else {
        if ((*(short *)(local_18 + 0x46) == 0x6ae) && (*(char *)(param_2 + 0x478) == '\x01')) {
          FUN_8000bb18(param_1,0x2c0);
          return;
        }
        FUN_80014aa0((double)FLOAT_803e6f2c);
        *(char *)(param_2 + 0x468) = *(char *)(param_2 + 0x468) - (char)local_14[0];
        FUN_8000bb18(param_1,0x2ac);
        *(byte *)(param_2 + 0x339) = *(byte *)(param_2 + 0x339) & 0x7f | 0x80;
        FUN_8002ac30(param_1,0x4b,200,0,0,1);
        *(float *)(param_2 + 0x328) = FLOAT_803e6f34;
        *(undefined *)(param_2 + 0x338) = 1;
        *(undefined2 *)(param_2 + 0x33a) = 0;
        *(undefined2 *)(param_2 + 0x33c) = 0;
        fVar2 = FLOAT_803e6ecc;
        *(float *)(param_2 + 0x32c) = FLOAT_803e6ecc;
        *(float *)(param_2 + 0x330) = fVar2;
        FUN_8000fad8();
        FUN_8000e67c((double)FLOAT_803e6f2c);
      }
    }
    cVar1 = *(char *)(param_2 + 0x478);
    if ((((cVar1 == '\x04') || (cVar1 == '\x05')) || (cVar1 == '\x06')) ||
       ('\0' < *(char *)(param_2 + 0x468))) {
      if (*(char *)(*(int *)(param_1 + 0xb8) + 0x468) < '\x04') {
        FUN_8000da58(param_1,0x37f);
      }
    }
    else {
      FUN_8022f148(*(undefined4 *)(param_2 + 0x10),0,0);
      if (*(char *)(param_1 + 0xac) == '&') {
        FUN_800200e8(0xe74,1);
      }
      *(undefined *)(param_2 + 0x478) = 4;
      *(float *)(param_2 + 0x46c) = FLOAT_803e6f30;
      FUN_8000bb18(param_1,0x380);
      FUN_8000a518(0xd6,1);
      FUN_8004350c(0,0,1);
      FUN_80042f78(0x29);
      uVar4 = FUN_800481b0(0x29);
      FUN_80043560(uVar4,0);
    }
  }
  return;
}

