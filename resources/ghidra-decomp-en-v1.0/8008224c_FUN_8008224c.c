// Function: FUN_8008224c
// Entry: 8008224c
// Size: 592 bytes

void FUN_8008224c(int param_1,int param_2)

{
  undefined4 uVar1;
  uint uVar2;
  int iVar3;
  int local_28;
  undefined auStack36 [4];
  short local_20;
  short local_1e;
  
  if (*(short *)(param_2 + 0x18) != -1) {
    *(undefined2 *)(param_1 + 100) = 0;
    *(undefined2 *)(param_1 + 0x62) = 0;
    uVar2 = (uint)*(short *)(param_2 + 0x18);
    if ((uVar2 & 0x8000) == 0) {
      iVar3 = uVar2 + 1;
    }
    else {
      FUN_8001f71c(DAT_803dd0d4,0xf,((int)(uVar2 & 0x7ff0) >> 4) << 1,8);
      iVar3 = (int)*DAT_803dd0d4 + (uVar2 & 0xf);
    }
    iVar3 = FUN_80043588(0xe,iVar3,&local_28);
    if (iVar3 == 0) {
      FUN_80137948(s__objLoadAnimdata__Warning_ACRomT_8030ef28);
    }
    else {
      FUN_800464c8(0xd,auStack36,local_28,8,0,0,0);
      iVar3 = FUN_80291614(auStack36,&DAT_803db734,4);
      if ((iVar3 == 0) || (iVar3 = FUN_80291614(auStack36,&DAT_803db73c,4), iVar3 == 0)) {
        *(short *)(param_1 + 0x62) = local_1e;
        if (local_20 == 0) {
          FUN_80137948(s__objLoadAnimdata__Warning_ACRomT_8030ef28);
        }
        else {
          uVar1 = FUN_80023cc8((int)local_20,0x11,0);
          *(undefined4 *)(param_1 + 0x94) = uVar1;
          if (*(int *)(param_1 + 0x94) == 0) {
            FUN_80137948(s__objLoadAnimdata__Warning_ACRomT_8030ef28);
          }
          else {
            FUN_800464c8(0xd,*(int *)(param_1 + 0x94),local_28 + 8,(int)local_20,0,0,0);
            *(short *)(param_1 + 100) = (short)(((int)local_20 >> 2) - (int)local_1e >> 1);
            *(int *)(param_1 + 0x98) = *(int *)(param_1 + 0x94) + local_1e * 4;
            *(undefined *)(param_1 + 0x57) = *(undefined *)(param_2 + 0x1f);
            if (-1 < *(char *)(param_1 + 0x57)) {
              (&DAT_8039a4b4)[*(char *)(param_1 + 0x57)] = 0;
              (&DAT_8039a45c)[*(char *)(param_1 + 0x57)] = 0;
              (&DAT_8039a358)[*(char *)(param_1 + 0x57)] = 0;
            }
            if (*(char *)(param_2 + 0x22) == '\0') {
              *(undefined *)(param_1 + 0x7e) = 0;
            }
            else {
              *(undefined *)(param_1 + 0x7e) = 2;
            }
            FUN_8008210c(param_1);
          }
        }
      }
      else {
        FUN_80137948(s__objLoadAnimdata__Warning_ACRomT_8030ef28);
      }
    }
  }
  return;
}

