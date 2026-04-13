// Function: FUN_8025024c
// Entry: 8025024c
// Size: 356 bytes

void FUN_8025024c(undefined4 param_1)

{
  uint uVar1;
  uint uVar2;
  
  if (DAT_803dec68 != 1) {
    uVar1 = DAT_800000f8 / 500000;
    DAT_803dec74 = (uVar1 * 0x7b24) / 8000;
    DAT_803dec7c = (uVar1 * 0xa428) / 8000;
    DAT_803dec84 = (uVar1 * 42000) / 8000;
    DAT_803dec8c = (uVar1 * 63000) / 8000;
    DAT_803dec94 = (uVar1 * 3000) / 8000;
    uVar1 = DAT_cc006c00;
    DAT_803dec70 = 0;
    DAT_803dec78 = 0;
    DAT_803dec80 = 0;
    DAT_803dec88 = 0;
    DAT_803dec90 = 0;
    uVar2 = DAT_cc006c04;
    DAT_cc006c00 = uVar1 & 0xffffffdf | 0x20;
    DAT_cc006c04 = uVar2 & 0xffff00ff;
    uVar1 = DAT_cc006c04;
    DAT_cc006c04 = uVar1 & 0xffffff00;
    DAT_cc006c0c = 0;
    FUN_80250110(1);
    FUN_8025001c(0);
    DAT_803dec58 = 0;
    DAT_803dec5c = 0;
    DAT_803dec60 = param_1;
    FUN_80243ec0(5,&LAB_80250438);
    FUN_802442c4(0x4000000);
    FUN_80243ec0(8,&LAB_802503bc);
    FUN_802442c4(0x800000);
    DAT_803dec68 = 1;
  }
  return;
}

