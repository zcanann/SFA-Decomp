// Function: FUN_8022be14
// Entry: 8022be14
// Size: 700 bytes

void FUN_8022be14(int param_1,int param_2)

{
  double dVar1;
  int iVar2;
  
  iVar2 = param_2 + 0xc0;
  (**(code **)(*DAT_803dcaa8 + 0x10))((double)FLOAT_803db414,param_1,iVar2);
  (**(code **)(*DAT_803dcaa8 + 0x14))(param_1,iVar2);
  (**(code **)(*DAT_803dcaa8 + 0x18))((double)FLOAT_803db414,param_1,iVar2);
  dVar1 = DOUBLE_803e6ee8;
  if ((*(char *)(param_2 + 0x338) == '\0') || (*(char *)(param_2 + 0x478) == '\x04')) {
    if (*(byte *)(param_2 + 800) != 0) {
      if (*(char *)(param_2 + 0x478) == '\x04') {
        *(undefined *)(param_2 + 0x478) = 5;
        *(float *)(param_2 + 0x46c) = FLOAT_803e6f24;
        *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
        FUN_8009ab70((double)FLOAT_803e6f28,param_1,1,0,1,1,0,1,0);
      }
      else {
        if (((*(byte *)(param_2 + 800) & 1) == 0) || (*(char *)(param_2 + 0x178) != '\b')) {
          *(char *)(param_2 + 0x468) = *(char *)(param_2 + 0x468) + -1;
        }
        else {
          *(undefined *)(param_2 + 0x468) = 0;
        }
        FUN_80014aa0((double)FLOAT_803e6f2c);
        if (*(char *)(param_2 + 0x468) < '\x01') {
          FUN_8022f148(*(undefined4 *)(param_2 + 0x10),0,0);
          if (*(char *)(param_1 + 0xac) == '&') {
            FUN_800200e8(0xe74,1);
          }
          else {
            *(undefined *)(param_2 + 0x478) = 4;
          }
          *(float *)(param_2 + 0x46c) = FLOAT_803e6f30;
          FUN_8000bb18(param_1,0x380);
          FUN_8000a518(0xd6,1);
        }
        else if (*(char *)(*(int *)(param_1 + 0xb8) + 0x468) < '\x04') {
          FUN_8000da58(param_1,0x37f);
        }
        FUN_8000bb18(param_1,0x2a0);
        *(byte *)(param_2 + 0x339) = *(byte *)(param_2 + 0x339) & 0x7f | 0x80;
        FUN_8002ac30(param_1,0x4b,200,0,0,1);
        *(float *)(param_2 + 0x328) = FLOAT_803e6f34;
        *(undefined *)(param_2 + 0x338) = 1;
        *(undefined2 *)(param_2 + 0x33a) = 0;
        *(undefined2 *)(param_2 + 0x33c) = 0;
        *(undefined4 *)(param_2 + 0x32c) = *(undefined4 *)(param_2 + 0x260);
        *(undefined4 *)(param_2 + 0x330) = *(undefined4 *)(param_2 + 0x264);
        FUN_8000fad8();
        FUN_8000e67c((double)FLOAT_803e6f38);
      }
    }
  }
  else {
    *(short *)(param_2 + 0x33a) =
         (short)(int)(FLOAT_803e6f3c * FLOAT_803db414 +
                     (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x33a)) -
                            DOUBLE_803e6ee8));
    *(short *)(param_2 + 0x33c) =
         (short)(int)(FLOAT_803e6f40 * FLOAT_803db414 +
                     (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x33c)) - dVar1
                            ));
  }
  return;
}

