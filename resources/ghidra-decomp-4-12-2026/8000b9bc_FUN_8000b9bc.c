// Function: FUN_8000b9bc
// Entry: 8000b9bc
// Size: 276 bytes

/* WARNING: Removing unreachable block (ram,0x8000bab0) */

void FUN_8000b9bc(double param_1,int param_2,short param_3,byte param_4)

{
  uint *puVar1;
  uint unaff_GQR0;
  
  if ((unaff_GQR0 & 0x3f00) != 0) {
    ldexpf((byte)(unaff_GQR0 >> 8) & 0x3f);
  }
  if (param_3 == 0) {
    puVar1 = (uint *)0x0;
  }
  else {
    puVar1 = (uint *)FUN_8000cd0c(param_2,0,param_3,2);
  }
  if (puVar1 != (uint *)0x0) {
    if (param_4 != 0xfe) {
      if (param_4 == 0xff) {
        param_4 = 100;
      }
      *(byte *)((int)puVar1 + 7) = param_4;
      if (*(char *)(puVar1 + 1) == '\0') {
        if (*(char *)((int)puVar1 + 6) != '\0') {
          param_4 = 0;
        }
        FUN_80272f0c(*puVar1,7,param_4);
      }
      else {
        FUN_8000c6e0(puVar1);
      }
    }
    if (param_1 < (double)FLOAT_803df1f0) {
      param_1 = (double)FLOAT_803df1f0;
    }
    if ((double)FLOAT_803df1f4 < param_1) {
      param_1 = (double)FLOAT_803df1f4;
    }
    FUN_80272f6c(*puVar1,0x80,(int)((double)FLOAT_803df1f8 * param_1));
  }
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-((byte)(unaff_GQR0 >> 0x18) & 0x3f));
  }
  return;
}

