
#ifndef NDEBUG
    #define PRINT(X)    printf("%s = %02hhX\n", __func__, X)
#else
    #define PRINT(X)    (X = X)
#endif