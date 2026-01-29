#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// n - number of parties
#define n 7
// d - number of probes
#define d 3
// k - number of secrets
#define k 3

/* Log table */
uint16_t log_table[256] = {

   509, 0, 25, 1, 50, 2, 26, 198, 75, 199, 27, 104, 51, 238, 223, 3, 
   100, 4, 224, 14, 52, 141, 129, 239, 76, 113, 8, 200, 248, 105, 28, 193, 
   125, 194, 29, 181, 249, 185, 39, 106, 77, 228, 166, 114, 154, 201, 9, 120, 
   101, 47, 138, 5, 33, 15, 225, 36, 18, 240, 130, 69, 53, 147, 218, 142, 
   150, 143, 219, 189, 54, 208, 206, 148, 19, 92, 210, 241, 64, 70, 131, 56, 
   102, 221, 253, 48, 191, 6, 139, 98, 179, 37, 226, 152, 34, 136, 145, 16, 
   126, 110, 72, 195, 163, 182, 30, 66, 58, 107, 40, 84, 250, 133, 61, 186, 
   43, 121, 10, 21, 155, 159, 94, 202, 78, 212, 172, 229, 243, 115, 167, 87, 
   175, 88, 168, 80, 244, 234, 214, 116, 79, 174, 233, 213, 231, 230, 173, 232, 
   44, 215, 117, 122, 235, 22, 11, 245, 89, 203, 95, 176, 156, 169, 81, 160, 
   127, 12, 246, 111, 23, 196, 73, 236, 216, 67, 31, 45, 164, 118, 123, 183, 
   204, 187, 62, 90, 251, 96, 177, 134, 59, 82, 161, 108, 170, 85, 41, 157, 
   151, 178, 135, 144, 97, 190, 220, 252, 188, 149, 207, 205, 55, 63, 91, 209, 
   83, 57, 132, 60, 65, 162, 109, 71, 20, 42, 158, 93, 86, 242, 211, 171, 
   68, 17, 146, 217, 35, 32, 46, 137, 180, 124, 184, 38, 119, 153, 227, 165, 
   103, 74, 237, 222, 197, 49, 254, 24, 13, 99, 140, 128, 192, 247, 112, 7, 
};

/* Antilog table */
uint8_t antilog_table[1019] = {

   1, 3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161, 248, 19, 53, 
   95, 225, 56, 72, 216, 115, 149, 164, 247, 2, 6, 10, 30, 34, 102, 170, 
   229, 52, 92, 228, 55, 89, 235, 38, 106, 190, 217, 112, 144, 171, 230, 49, 
   83, 245, 4, 12, 20, 60, 68, 204, 79, 209, 104, 184, 211, 110, 178, 205, 
   76, 212, 103, 169, 224, 59, 77, 215, 98, 166, 241, 8, 24, 40, 120, 136, 
   131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206, 73, 219, 118, 154, 
   181, 196, 87, 249, 16, 48, 80, 240, 11, 29, 39, 105, 187, 214, 97, 163, 
   254, 25, 43, 125, 135, 146, 173, 236, 47, 113, 147, 174, 233, 32, 96, 160, 
   251, 22, 58, 78, 210, 109, 183, 194, 93, 231, 50, 86, 250, 21, 63, 65, 
   195, 94, 226, 61, 71, 201, 64, 192, 91, 237, 44, 116, 156, 191, 218, 117, 
   159, 186, 213, 100, 172, 239, 42, 126, 130, 157, 188, 223, 122, 142, 137, 128, 
   155, 182, 193, 88, 232, 35, 101, 175, 234, 37, 111, 177, 200, 67, 197, 84, 
   252, 31, 33, 99, 165, 244, 7, 9, 27, 45, 119, 153, 176, 203, 70, 202, 
   69, 207, 74, 222, 121, 139, 134, 145, 168, 227, 62, 66, 198, 81, 243, 14, 
   18, 54, 90, 238, 41, 123, 141, 140, 143, 138, 133, 148, 167, 242, 13, 23, 
   57, 75, 221, 124, 132, 151, 162, 253, 28, 36, 108, 180, 199, 82, 246, 1, 
   3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161, 248, 19, 53, 95, 
   225, 56, 72, 216, 115, 149, 164, 247, 2, 6, 10, 30, 34, 102, 170, 229, 
   52, 92, 228, 55, 89, 235, 38, 106, 190, 217, 112, 144, 171, 230, 49, 83, 
   245, 4, 12, 20, 60, 68, 204, 79, 209, 104, 184, 211, 110, 178, 205, 76, 
   212, 103, 169, 224, 59, 77, 215, 98, 166, 241, 8, 24, 40, 120, 136, 131, 
   158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206, 73, 219, 118, 154, 181, 
   196, 87, 249, 16, 48, 80, 240, 11, 29, 39, 105, 187, 214, 97, 163, 254, 
   25, 43, 125, 135, 146, 173, 236, 47, 113, 147, 174, 233, 32, 96, 160, 251, 
   22, 58, 78, 210, 109, 183, 194, 93, 231, 50, 86, 250, 21, 63, 65, 195, 
   94, 226, 61, 71, 201, 64, 192, 91, 237, 44, 116, 156, 191, 218, 117, 159, 
   186, 213, 100, 172, 239, 42, 126, 130, 157, 188, 223, 122, 142, 137, 128, 155, 
   182, 193, 88, 232, 35, 101, 175, 234, 37, 111, 177, 200, 67, 197, 84, 252, 
   31, 33, 99, 165, 244, 7, 9, 27, 45, 119, 153, 176, 203, 70, 202, 69, 
   207, 74, 222, 121, 139, 134, 145, 168, 227, 62, 66, 198, 81, 243, 14, 18, 
   54, 90, 238, 41, 123, 141, 140, 143, 138, 133, 148, 167, 242, 13, 23, 57, 
   75, 221, 124, 132, 151, 162, 253, 28, 36, 108, 180, 199, 82, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
};


#define generate_random_poly() ((uint8_t)random())
#define get_zero() 0b00000000
#define poly_add(f, g) (f ^ g)
#define poly_mult(f, g) antilog_table[log_table[(f)] + log_table[(g)]]

#define polynomial_interpolation_packed_old(sharing)                                                  \
    ({                                                                                              \
    unsigned char sum = 0;                                                                        \
    sum = poly_add(poly_mult(sharing[0], M_inverse[0][0]), poly_mult(sharing[1], M_inverse[1][0]));           \
    sum;                                                                                          \
    })

#define polynomial_sharing_packed_old(sharing, s, rand)                       \
  {                                                                            \
    sharing[0] = poly_add(poly_mult((s), M[0][0]), poly_mult((rand), M[1][0])); \
    sharing[1] = poly_add(poly_mult((s), M[0][1]), poly_mult((rand), M[1][1]));                                                                        \
  }



uint8_t x[2] = {1, 2};
uint8_t vand_x[2][2] = {{0b00000001, 0b00000001}, {0b00000001, 0b00000010}};

uint8_t M[d+1][n] = {{0b10100101, 0b11110101, 0b00000010, 0b00101100, 0b11011100, 0b10000110, 0b00100100}, 
{0b11110101, 0b00000111, 0b00000100, 0b01100010, 0b01101000, 0b10000100, 0b01111000}, 
{0b00000010, 0b00000100, 0b01101110, 0b01000100, 0b00100001, 0b01011000, 0b01010101}, 
{0b01010011, 0b11110111, 0b01101001, 0b00001011, 0b10010100, 0b01011011, 0b00001000}};
uint8_t M_inverse[n][d+1] = {{0b11100000, 0b00001111, 0b00000010, 0b10011100}, 
{0b01110111, 0b11100111, 0b10010010, 0b10000101}, 
{0b10100101, 0b00101100, 0b00111000, 0b01111011}, 
{0b01010101, 0b01001111, 0b01110100, 0b10101000}, 
{0b01001010, 0b01000001, 0b01111000, 0b10101100}, 
{0b10001110, 0b11100100, 0b01010011, 0b10100111}, 
{0b10100010, 0b00101111, 0b11110110, 0b11000000}};
uint8_t A_tilde[n][d] = {{0b00000001}, 
{0b10001100}, 
{0b10111000}, 
{0b01001111}, 
{0b10110001}, 
{0b00001011}, 
{0b00001010}};

void polynomial_sharing_packed(uint8_t sharing[n], uint8_t points[d+1]){   

  for (int i = 0; i < n; i++) {
        for (int j = 0; j < d+1; j++) {
          sharing[i] = poly_add(sharing[i], poly_mult(points[j],  M[j][i]));
        }
    }
                                                                  
}    

void polynomial_interpolation_packed(uint8_t result[n], uint8_t sharing[n]){
  for (int i = 0; i < k; i++)
  {
    for (int j = 0; j < n; j++)
    {
      result[i] = poly_add(result[i], poly_mult(sharing[j], M_inverse[j][i]));                
    }
  }             
}  

void sw_add(uint8_t res[n], uint8_t f[n], uint8_t g[n]){
  for (int i = 0; i < n; i++)
  {
    res[i] = poly_add(f[i], g[i]);
  }
  
}                                      
  //(res)[2] = poly_add((f)[2], (g)[2]);

void optZEnc(uint8_t g[n], int h){

    for (int i = 0; i < d + 1 - (k+h); i++){
        g[i] = generate_random_poly();
    }
    
    for (int l = 0; l < h; l++){
        g[d-k+l] = get_zero();
    }

    for (int i = d+1-k; i < n; i++){
        for (int j = 0; j < d-k + 1; j++){ 
            g[i] = poly_add(g[i], poly_mult(g[j], A_tilde[i][j]));
        }
    }
} 

void optsZEnc(uint8_t res[n]){

  uint8_t g[n];
  memset(g, 0, n * sizeof(char));

  for (int j = 0; j < d-k; j++){
    optZEnc(g, j);
    sw_add(res, res, g);
  }

} 

static uint32_t xorshift32() {
  static unsigned int state = 0xDEADBEEF; // Initial seed
  state ^= state << 13;
  state ^= state >> 17;
  state ^= state << 5;
  return state;
}

int main(int argc, char const *argv[]){
    /*unsigned char s = 10;
    unsigned char f[d + 1];  
    unsigned char sharing[d + 1];         
    uint8_t alpha[2] = {1, 2};   
    uint8_t inverse_vand[2][2] = {{0b11110111, 0b11110110}, {0b11110110, 0b11110110}};                               
    f[0] = (s);                                                                
    f[1] = ((uint8_t)xorshift32());                                             
    (sharing)[0] = poly_add(f[0], poly_mult(f[1], alpha[0]));                  
    (sharing)[1] = poly_add(f[0], poly_mult(f[1], alpha[1]));  


    uint8_t result[2];
    memset(result, 0, n * sizeof(char));
    cZEnc(result);  
    printf("s 0: %d \n", sharing[0]);
    printf("r 0: %d \n", result[0]);
    printf("s 1: %d \n", sharing[1]);
    printf("r 1: %d \n", result[1]);
    //change result for correct Zenc
    sharing[0] = poly_add(sharing[0], result[0]);
    sharing[1] = poly_add(sharing[1], result[1]);
    printf("s+r 0: %d \n", sharing[0]);
    printf("s+r 1: %d \n", sharing[1]);


    unsigned char sum = get_zero();                                            
    sum = poly_add(sum, poly_mult(inverse_vand[0][0], sharing[0]));            
    sum = poly_add(sum, poly_mult(inverse_vand[0][1], sharing[1]));            
    printf("%d \n", s);             
    printf("%d \n", sum);*/

    /*
    uint8_t s = 10;
    uint8_t rand = 11;
    uint8_t f[d + 1];
    printf("secret: %d \n", s);
    printf("random: %d \n", rand);
    f[0] = poly_add(poly_mult(s, M[0][0]), poly_mult(rand, M[1][0]));
    f[1] = poly_add(poly_mult(s, M[0][1]), poly_mult(rand, M[1][1]));

    uint8_t result[2];
    memset(result, 0, n * sizeof(char));
    cZEnc(result); 
    f[0] = poly_add(f[0], result[0]);
    f[1] = poly_add(f[1], result[1]);
    

    printf("secret_share: %d \n", f[0]);
    printf("random_share: %d \n", f[1]);
    uint8_t rec_s;
    uint8_t rec_rand;
    rec_s = poly_add(poly_mult(f[0], M_inverse[0][0]), poly_mult(f[1], M_inverse[1][0]));
    rec_rand = poly_add(poly_mult(f[0], M_inverse[0][1]), poly_mult(f[1], M_inverse[1][1]));
    printf("secret: %d \n", rec_s);
    printf("random: %d \n", rec_rand);*/

    // first k values are the secrets, rest are the random coefficients
    /*uint8_t points[d+1] = {10,136,198,20};
    uint8_t f[n];
    memset(f, 0, n * sizeof(char));
    
    polynomial_sharing_packed(f,points);
    
    uint8_t result[n];
    memset(result, 0, n * sizeof(char));
    optZEnc(result, 0); 

    for (int i = 0; i < n; i++)
    {
      f[i] = poly_add(f[i], result[i]);
    }

    uint8_t reconstruct_secrets[k];
    memset(reconstruct_secrets, 0, k * sizeof(char));
    polynomial_interpolation_packed(reconstruct_secrets, f);

    printf("Real Secrets:");
    for (int i = 0; i < k; i++)
    {
      printf("%d,", points[i]);
    }
    printf("\n Reconstructed Secrets:");

    for (int i = 0; i < k; i++)
    {
      printf("%d,", reconstruct_secrets[i]);
    }
    printf("\n Finish \n");   */

    uint8_t points[d+1] = {10,136,198,20};
    uint8_t f[n];
    memset(f, 0, n * sizeof(char));
    
    polynomial_sharing_packed(f,points);
    
    uint8_t result[n];
    memset(result, 0, n * sizeof(char));
    optsZEnc(result); 

    for (int i = 0; i < n; i++)
    {
      f[i] = poly_add(f[i], result[i]);
    }

    uint8_t reconstruct_secrets[k];
    memset(reconstruct_secrets, 0, k * sizeof(char));
    polynomial_interpolation_packed(reconstruct_secrets, f);

    printf("Real Secrets:");
    for (int i = 0; i < k; i++)
    {
      printf("%d,", points[i]);
    }
    printf("\n Reconstructed Secrets:");

    for (int i = 0; i < k; i++)
    {
      printf("%d,", reconstruct_secrets[i]);
    }
    printf("\n Finish \n");   
}

