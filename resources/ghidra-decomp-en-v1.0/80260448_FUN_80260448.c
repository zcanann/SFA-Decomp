// Function: FUN_80260448
// Entry: 80260448
// Size: 100 bytes

undefined4
FUN_80260448(int param_1,undefined4 param_2,uint param_3,undefined4 param_4,undefined4 param_5)

{
  undefined4 uVar1;
  int iVar2;
  
  iVar2 = param_1 * 0x110;
  if ((&DAT_803af1e0)[param_1 * 0x44] == 0) {
    uVar1 = 0xfffffffd;
  }
  else {
    *(undefined4 *)(&DAT_803af2b4 + iVar2) = param_5;
    *(uint *)(&DAT_803af28c + iVar2) = param_3 >> 7;
    *(undefined4 *)(&DAT_803af290 + iVar2) = param_2;
    *(undefined4 *)(&DAT_803af294 + iVar2) = param_4;
    uVar1 = FUN_8025eaf8(param_1,&LAB_8026036c);
  }
  return uVar1;
}

