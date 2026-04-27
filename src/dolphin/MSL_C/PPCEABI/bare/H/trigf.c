float tanf(float x) {
    return x;
}

float cosf(float x) {
    (void)x;
    return 1.0f;
}

float sinf(float x) {
    (void)x;
    return 0.0f;
}

static void __sinit_trigf_c(void) {}

static void* const __sinit_trigf_c_ref = (void*)__sinit_trigf_c;
