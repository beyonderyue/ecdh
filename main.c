#include <openssl/ssl.h>  
#include <unistd.h>

#define ECDH_SIZE 33  
  
void handleErrors()  
{  
    printf("Error occurred.\n");  
}  
static void disp(const char *str, const void *pbuf, const int size)  
{  
    int i=0;  
    if(str != NULL){  
        printf("%s:\n", str);  
    }  
    if(pbuf != NULL && size > 0){  
        for(i=0;i<size;i++)  
            printf("%02x", *((unsigned char *)pbuf+i));  
        putchar('\n');  
    }  
    putchar('\n');  
}  
int main() {  
    EC_KEY *ecdh; 
    EC_POINT *point = NULL;  
    EC_POINT *point2c;  
    EC_GROUP *group; 
    BIGNUM *privkey;
    char *privkeyh; 
    unsigned char pubkey[ECDH_SIZE];
    unsigned char pubkey2[ECDH_SIZE] = {0x03, 0xc5, 0x63, 0x7e, 0xd4, 0xdd, 0x47, 0x22, 0x7f, 0x46, 0x19, 0x0b, 0x09, 0xa7, 0xb8, 0x2e, 0x9a, 0xac, 0x1e, 0xc7, 0x22, 0x6c, 0x4f, 0x5b, 0xd3, 0xc4, 0x32, 0xbd, 0xbd, 0xc7, 0x67, 0xdb, 0x0a};//This pubkey from JAVA implementation
    unsigned char shared[ECDH_SIZE];  
    int len;  
    FILE *f  = NULL;
    //Generate Public  
    ecdh = EC_KEY_new();
    ecdh = EC_KEY_new_by_curve_name(NID_secp256k1);

    f = fopen("b.ecc", "rb");
    if (f == NULL) {
        f = fopen("b.ecc", "wb");
        EC_KEY_generate_key(ecdh);
        if (f != NULL) {
            PEM_write_ECPrivateKey(f, ecdh, NULL, NULL, 512, NULL, NULL);
        }
        fclose(f);
        f = NULL;
    } else {
        ecdh = PEM_read_ECPrivateKey(f, NULL, NULL, NULL);        
        fclose(f);
        f = NULL;
    }
    
    point = EC_KEY_get0_public_key(ecdh);  
    group = EC_KEY_get0_group(ecdh);  
    if(0 == (len = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, pubkey, ECDH_SIZE, NULL))) handleErrors();  
    disp("Bob Pubkey: ", pubkey, ECDH_SIZE);//This pubkey from openssl implementation  
    point2c = EC_POINT_new(group);
    EC_POINT_oct2point(group, point2c, pubkey2, ECDH_SIZE, NULL); 
    if(0 == (len = ECDH_compute_key(shared, ECDH_SIZE, point2c, ecdh, NULL))) handleErrors();  
    disp("Bob's secret: ", shared, len);  
    EC_POINT_free(point2c);  
    EC_KEY_free(ecdh);  
    return 0;  
} 
