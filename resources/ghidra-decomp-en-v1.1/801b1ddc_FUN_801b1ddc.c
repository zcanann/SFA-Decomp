// Function: FUN_801b1ddc
// Entry: 801b1ddc
// Size: 656 bytes

/* WARNING: Removing unreachable block (ram,0x801b204c) */
/* WARNING: Removing unreachable block (ram,0x801b2044) */
/* WARNING: Removing unreachable block (ram,0x801b1df4) */
/* WARNING: Removing unreachable block (ram,0x801b1dec) */

void FUN_801b1ddc(void)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  char *pcVar4;
  double in_f30;
  double dVar5;
  double dVar6;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  undefined auStack_68 [8];
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar1 = FUN_80286840();
  pcVar4 = *(char **)(uVar1 + 0xb8);
  iVar3 = *(int *)(uVar1 + 0x4c);
  *(byte *)(uVar1 + 0xaf) = *(byte *)(uVar1 + 0xaf) | 8;
  if (pcVar4[1] == '\0') {
    if (*pcVar4 < '\x01') {
      uStack_4c = (int)*(char *)(iVar3 + 0x19) ^ 0x80000000;
      local_50 = 0x43300000;
      local_60 = (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e5528) / FLOAT_803e5518;
      local_54 = FLOAT_803e551c;
      iVar2 = 0x2d;
      dVar5 = (double)FLOAT_803e5520;
      dVar6 = DOUBLE_803e5528;
      do {
        uStack_4c = FUN_80022264(0xffffff06,0xfa);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        local_5c = local_60 *
                   (float)(dVar5 * (double)(float)((double)CONCAT44(0x43300000,uStack_4c) - dVar6));
        uStack_44 = FUN_80022264(0,0x1c2);
        uStack_44 = uStack_44 ^ 0x80000000;
        local_48 = 0x43300000;
        local_58 = local_60 *
                   (float)(dVar5 * (double)(float)((double)CONCAT44(0x43300000,uStack_44) - dVar6));
        (**(code **)(*DAT_803dd708 + 8))(uVar1,0x7f9,auStack_68,2,0xffffffff,0);
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
      iVar2 = 0x19;
      dVar5 = (double)FLOAT_803e5520;
      dVar6 = DOUBLE_803e5528;
      do {
        uStack_44 = FUN_80022264(0xffffff06,0xfa);
        uStack_44 = uStack_44 ^ 0x80000000;
        local_48 = 0x43300000;
        local_5c = local_60 *
                   (float)(dVar5 * (double)(float)((double)CONCAT44(0x43300000,uStack_44) - dVar6));
        uStack_4c = FUN_80022264(0,0x1c2);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        local_58 = local_60 *
                   (float)(dVar5 * (double)(float)((double)CONCAT44(0x43300000,uStack_4c) - dVar6));
        (**(code **)(*DAT_803dd708 + 8))(uVar1,0x7fa,auStack_68,2,0xffffffff,0);
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
      if (*(int *)(iVar3 + 0x14) != 0x1d09) {
        FUN_8000bb38(uVar1,0x47b);
      }
      pcVar4[1] = '\x01';
      if ((int)*(short *)(iVar3 + 0x1e) != 0xffffffff) {
        FUN_800201ac((int)*(short *)(iVar3 + 0x1e),1);
      }
    }
    else {
      iVar3 = FUN_8002ba84();
      if (iVar3 != 0) {
        if ((*(byte *)(uVar1 + 0xaf) & 4) != 0) {
          (**(code **)(**(int **)(iVar3 + 0x68) + 0x28))(iVar3,uVar1,1,4);
        }
        *(byte *)(uVar1 + 0xaf) = *(byte *)(uVar1 + 0xaf) & 0xf7;
        FUN_80041110();
      }
    }
  }
  FUN_8028688c();
  return;
}

