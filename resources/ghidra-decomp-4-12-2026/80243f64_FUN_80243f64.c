// Function: FUN_80243f64
// Entry: 80243f64
// Size: 728 bytes

uint FUN_80243f64(uint param_1,uint param_2)

{
  int iVar1;
  ushort uVar3;
  uint uVar2;
  
  iVar1 = countLeadingZeros(param_1);
  if (iVar1 < 0xc) {
    if (iVar1 == 8) {
      uVar2 = DAT_cc006c00;
      uVar2 = uVar2 & 0xffffffd3;
      if ((param_2 & 0x800000) == 0) {
        uVar2 = uVar2 | 4;
      }
      DAT_cc006c00 = uVar2;
      param_1 = param_1 & 0xff7fffff;
    }
    else if (iVar1 < 8) {
      if (iVar1 < 5) {
        if (-1 < iVar1) {
          uVar3 = (ushort)((param_2 & 0x80000000) == 0);
          if ((param_2 & 0x40000000) == 0) {
            uVar3 = uVar3 | 2;
          }
          if ((param_2 & 0x20000000) == 0) {
            uVar3 = uVar3 | 4;
          }
          if ((param_2 & 0x10000000) == 0) {
            uVar3 = uVar3 | 8;
          }
          if ((param_2 & 0x8000000) == 0) {
            uVar3 = uVar3 | 0x10;
          }
          DAT_cc00401c = uVar3;
          param_1 = param_1 & 0x7ffffff;
        }
      }
      else {
        uVar3 = DAT_cc00500a;
        uVar3 = uVar3 & 0xfe07;
        if ((param_2 & 0x4000000) == 0) {
          uVar3 = uVar3 | 0x10;
        }
        if ((param_2 & 0x2000000) == 0) {
          uVar3 = uVar3 | 0x40;
        }
        if ((param_2 & 0x1000000) == 0) {
          uVar3 = uVar3 | 0x100;
        }
        DAT_cc00500a = uVar3;
        param_1 = param_1 & 0xf8ffffff;
      }
    }
    else {
      uVar2 = DAT_cc006800;
      uVar2 = uVar2 & 0xffffd3f0;
      if ((param_2 & 0x400000) == 0) {
        uVar2 = uVar2 | 1;
      }
      if ((param_2 & 0x200000) == 0) {
        uVar2 = uVar2 | 4;
      }
      if ((param_2 & 0x100000) == 0) {
        uVar2 = uVar2 | 0x400;
      }
      DAT_cc006800 = uVar2;
      param_1 = param_1 & 0xff8fffff;
    }
  }
  else if (iVar1 < 0x11) {
    if (iVar1 < 0xf) {
      uVar2 = DAT_cc006814;
      uVar2 = uVar2 & 0xfffff3f0;
      if ((param_2 & 0x80000) == 0) {
        uVar2 = uVar2 | 1;
      }
      if ((param_2 & 0x40000) == 0) {
        uVar2 = uVar2 | 4;
      }
      if ((param_2 & 0x20000) == 0) {
        uVar2 = uVar2 | 0x400;
      }
      DAT_cc006814 = uVar2;
      param_1 = param_1 & 0xfff1ffff;
    }
    else {
      uVar2 = DAT_cc006828;
      uVar2 = uVar2 & 0xfffffff0;
      if ((param_2 & 0x10000) == 0) {
        uVar2 = uVar2 | 1;
      }
      if ((param_2 & 0x8000) == 0) {
        uVar2 = uVar2 | 4;
      }
      DAT_cc006828 = uVar2;
      param_1 = param_1 & 0xfffe7fff;
    }
  }
  else if (iVar1 < 0x1b) {
    uVar2 = 0xf0;
    if ((param_2 & 0x4000) == 0) {
      uVar2 = 0x8f0;
    }
    if ((param_2 & 0x800) == 0) {
      uVar2 = uVar2 | 8;
    }
    if ((param_2 & 0x400) == 0) {
      uVar2 = uVar2 | 4;
    }
    if ((param_2 & 0x200) == 0) {
      uVar2 = uVar2 | 2;
    }
    if ((param_2 & 0x100) == 0) {
      uVar2 = uVar2 | 1;
    }
    if ((param_2 & 0x80) == 0) {
      uVar2 = uVar2 | 0x100;
    }
    if ((param_2 & 0x40) == 0) {
      uVar2 = uVar2 | 0x1000;
    }
    if ((param_2 & 0x2000) == 0) {
      uVar2 = uVar2 | 0x200;
    }
    if ((param_2 & 0x1000) == 0) {
      uVar2 = uVar2 | 0x400;
    }
    if ((param_2 & 0x20) == 0) {
      uVar2 = uVar2 | 0x2000;
    }
    DAT_cc003004 = uVar2;
    param_1 = param_1 & 0xffff801f;
  }
  return param_1;
}

