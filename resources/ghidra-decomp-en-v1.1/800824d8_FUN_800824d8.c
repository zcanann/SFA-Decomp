// Function: FUN_800824d8
// Entry: 800824d8
// Size: 592 bytes

void FUN_800824d8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  int iVar2;
  undefined8 extraout_f1;
  undefined8 uVar3;
  uint local_28;
  undefined auStack_24 [4];
  short local_20;
  short local_1e;
  
  if (*(short *)(param_10 + 0x18) != -1) {
    *(undefined2 *)(param_9 + 100) = 0;
    *(undefined2 *)(param_9 + 0x62) = 0;
    uVar1 = (uint)*(short *)(param_10 + 0x18);
    if ((uVar1 & 0x8000) == 0) {
      iVar2 = uVar1 + 1;
    }
    else {
      param_1 = FUN_8001f7e0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             DAT_803ddd54,0xf,((int)(uVar1 & 0x7ff0) >> 4) << 1,8,param_13,param_14,
                             param_15,param_16);
      iVar2 = (int)*DAT_803ddd54 + (uVar1 & 0xf);
    }
    iVar2 = FUN_80043680(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xe,iVar2,
                         &local_28);
    if (iVar2 == 0) {
      FUN_80137cd0();
    }
    else {
      uVar3 = FUN_80046644(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xd,
                           auStack_24,local_28,8,(uint *)0x0,0,0,param_16);
      iVar2 = FUN_80291d74((int)auStack_24,-0x7fc23c6c,4);
      if ((iVar2 == 0) || (iVar2 = FUN_80291d74((int)auStack_24,-0x7fc23c64,4), iVar2 == 0)) {
        *(short *)(param_9 + 0x62) = local_1e;
        if (local_20 == 0) {
          FUN_80137cd0();
        }
        else {
          iVar2 = FUN_80023d8c((int)local_20,0x11);
          *(int *)(param_9 + 0x94) = iVar2;
          if (*(int *)(param_9 + 0x94) == 0) {
            FUN_80137cd0();
          }
          else {
            FUN_80046644(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xd,
                         *(int *)(param_9 + 0x94),local_28 + 8,(int)local_20,(uint *)0x0,0,0,
                         param_16);
            *(short *)(param_9 + 100) = (short)(((int)local_20 >> 2) - (int)local_1e >> 1);
            *(int *)(param_9 + 0x98) = *(int *)(param_9 + 0x94) + local_1e * 4;
            *(undefined *)(param_9 + 0x57) = *(undefined *)(param_10 + 0x1f);
            if (-1 < *(char *)(param_9 + 0x57)) {
              (&DAT_8039b114)[*(char *)(param_9 + 0x57)] = 0;
              (&DAT_8039b0bc)[*(char *)(param_9 + 0x57)] = 0;
              (&DAT_8039afb8)[*(char *)(param_9 + 0x57)] = 0;
            }
            if (*(char *)(param_10 + 0x22) == '\0') {
              *(undefined *)(param_9 + 0x7e) = 0;
            }
            else {
              *(undefined *)(param_9 + 0x7e) = 2;
            }
            FUN_80082398(param_9);
          }
        }
      }
      else {
        FUN_80137cd0();
      }
    }
  }
  return;
}

