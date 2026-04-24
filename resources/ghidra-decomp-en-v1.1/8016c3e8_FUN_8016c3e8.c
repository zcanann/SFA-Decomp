// Function: FUN_8016c3e8
// Entry: 8016c3e8
// Size: 424 bytes

void FUN_8016c3e8(ushort *param_1)

{
  ushort *puVar1;
  int iVar2;
  float afStack_278 [12];
  float afStack_248 [12];
  float afStack_218 [12];
  float afStack_1e8 [12];
  float afStack_1b8 [12];
  float afStack_188 [3];
  float local_17c;
  float local_16c;
  float local_15c;
  float afStack_158 [12];
  float afStack_128 [12];
  float afStack_f8 [12];
  float afStack_c8 [12];
  float afStack_98 [12];
  float afStack_68 [12];
  float afStack_38 [12];
  
  if ((*(byte *)(*(int *)(param_1 + 0x5c) + 0x7f) & 4) == 0) {
    FUN_8003b9ec((int)param_1);
  }
  else {
    FUN_8002b554(param_1,afStack_38,'\0');
    iVar2 = *(int *)(param_1 + 0x26);
    FUN_80247a48(-(double)(*(float *)(iVar2 + 8) - FLOAT_803dda58),-(double)*(float *)(iVar2 + 0xc),
                 -(double)(*(float *)(iVar2 + 0x10) - FLOAT_803dda5c),afStack_68);
    FUN_80247618(afStack_68,afStack_38,afStack_98);
    puVar1 = (ushort *)(**(code **)(*DAT_803dd6d0 + 0xc))();
    puVar1[1] = puVar1[1] + 0x8000;
    *(float *)(puVar1 + 4) = FLOAT_803e3ec0;
    FUN_8002b554(puVar1,afStack_188,'\0');
    puVar1[1] = puVar1[1] + 0x8000;
    *(float *)(puVar1 + 4) = FLOAT_803e3ec4;
    FUN_80247a48(-(double)local_17c,-(double)local_16c,-(double)local_15c,afStack_c8);
    FUN_8024782c((double)FLOAT_803e3ec8,afStack_f8,0x79);
    FUN_8024782c((double)FLOAT_803e3ec8,afStack_128,0x7a);
    FUN_80247a48((double)local_17c,(double)local_16c,(double)local_15c,afStack_158);
    FUN_80247618(afStack_c8,afStack_188,afStack_1b8);
    FUN_80247618(afStack_f8,afStack_1b8,afStack_1e8);
    FUN_80247618(afStack_128,afStack_1e8,afStack_218);
    FUN_80247618(afStack_158,afStack_218,afStack_248);
    FUN_80247618(afStack_248,afStack_98,afStack_278);
    FUN_800413cc(afStack_278);
    FUN_80041bbc((int)param_1);
  }
  return;
}

