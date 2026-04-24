// Function: FUN_80082ad0
// Entry: 80082ad0
// Size: 288 bytes

void FUN_80082ad0(undefined4 param_1,int param_2,int *param_3)

{
  short *psVar1;
  undefined4 uVar2;
  
  if ((code *)param_3[0x3a] != (code *)0x0) {
    (*(code *)param_3[0x3a])(param_3[0x44],param_1);
    param_3[0x3a] = 0;
  }
  if (*(char *)((int)param_3 + 0x57) == DAT_803db720) {
    FUN_8000d0c0();
    DAT_803db720 = -1;
  }
  if (*(char *)((int)param_3 + 0x7e) != '\0') {
    if (*(char *)((int)param_3 + 0x7b) != '\0') {
      *(undefined *)((int)param_3 + 0x7b) = 0;
    }
    if (*param_3 != 0) {
      *(undefined4 *)(param_2 + 0xc0) = 0;
      *(ushort *)(param_2 + 0xb0) = *(ushort *)(param_2 + 0xb0) & 0xefff;
      *param_3 = 0;
    }
  }
  if ((*(byte *)((int)param_3 + 0x136) >> 2 & 1) != 0) {
    psVar1 = (short *)FUN_8002b9ec();
    uVar2 = FUN_800571e4();
    (**(code **)(*DAT_803dcaac + 0x1c))(psVar1 + 6,(int)*psVar1,0,uVar2);
    *(byte *)((int)param_3 + 0x136) = *(byte *)((int)param_3 + 0x136) & 0xfb;
  }
  *(undefined *)((int)param_3 + 0x7e) = 0;
  return;
}

