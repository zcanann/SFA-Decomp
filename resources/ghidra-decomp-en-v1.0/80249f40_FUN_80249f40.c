// Function: FUN_80249f40
// Entry: 80249f40
// Size: 204 bytes

void FUN_80249f40(void)

{
  undefined *puVar1;
  
  if (DAT_803ddf24 == 0xd) {
LAB_80249f88:
    FUN_8024b970();
    puVar1 = DAT_803ddf08;
    DAT_803ddf08 = &DAT_803adf80;
    if (*(code **)(puVar1 + 0x28) != (code *)0x0) {
      (**(code **)(puVar1 + 0x28))(0xfffffffc);
    }
    FUN_8024a1b8();
  }
  else {
    if (DAT_803ddf24 < 0xd) {
      if ((DAT_803ddf24 < 6) && (3 < DAT_803ddf24)) goto LAB_80249f88;
    }
    else if (DAT_803ddf24 == 0xf) goto LAB_80249f88;
    FUN_8024b2dc();
    FUN_80240d80(&DAT_803adfb0);
    FUN_80240fdc(&DAT_803adfb0,0x10624dd3,0,((DAT_800000f8 >> 2) / 1000) * 0x47e,&LAB_80249efc);
  }
  return;
}

