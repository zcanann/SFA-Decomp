// Function: FUN_80082d5c
// Entry: 80082d5c
// Size: 288 bytes

void FUN_80082d5c(undefined4 param_1,int param_2,int *param_3)

{
  short *psVar1;
  int iVar2;
  
  if ((code *)param_3[0x3a] != (code *)0x0) {
    (*(code *)param_3[0x3a])(param_3[0x44],param_1);
    param_3[0x3a] = 0;
  }
  if (*(char *)((int)param_3 + 0x57) == DAT_803dc380) {
    FUN_8000d0e0();
    DAT_803dc380 = -1;
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
    psVar1 = (short *)FUN_8002bac4();
    iVar2 = FUN_80057360();
    (**(code **)(*DAT_803dd72c + 0x1c))(psVar1 + 6,(int)*psVar1,0,iVar2);
    *(byte *)((int)param_3 + 0x136) = *(byte *)((int)param_3 + 0x136) & 0xfb;
  }
  *(undefined *)((int)param_3 + 0x7e) = 0;
  return;
}

