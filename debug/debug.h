
#ifndef NDEBUG
    #define PRINT(X)    printf("%s = %02hhX\n", __func__, X)
    #define PRINTS(X)    printf("%s: %s\n", __func__, X)
#else
    #define PRINT(X)    (X = X)
    #define PRINTS(X)
#endif