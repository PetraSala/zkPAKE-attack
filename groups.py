from random import randrange


def miller_rabin(n, k=10):
	if n == 2:
		return True
	if not n & 1:
		return False

	def check(a, s, d, n):
		x = pow(a, d, n)
		if x == 1:
			return True
		for i in range(s - 1):
			if x == n - 1:
				return True
			x = pow(x, 2, n)
		return x == n - 1

	s = 0
	d = n - 1

	while d % 2 == 0:
		d >>= 1
		s += 1

	for i in range(k):
		a = randrange(2, n - 1)
		if not check(a, s, d, n):
			return False
	return True


def getP(group):
    #Group 1: 1024-bit MODP Group with 160-bit Prime Order Subgroup
    #Group 2: 2048-bit MODP Group with 224-bit Prime Order Subgroup

    if group == 1:
        hexP = "B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6        9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0 13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70       98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0       A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708       DF1FB2BC 2E4A4371"
       
    else:
        if group ==2:
            hexP = " AD107E1E 9123A9D0 D660FAA7 9559C51F A20D64E5 683B9FD1        B54B1597 B61D0A75 E6FA141D F95A56DB AF9A3C40 7BA1DF15         EB3D688A 309C180E 1DE6B85A 1274A0A6 6D3F8152 AD6AC212         9037C9ED EFDA4DF8 D91E8FEF 55B7394B 7AD5B7D0 B6C12207         C9F98D11 ED34DBF6 C6BA0B2C 8BBC27BE 6A00E0A0 B9C49708         B3BF8A31 70918836 81286130 BC8985DB 1602E714  415D9330         278273C7 DE31EFDC 7310F712 1FD5A074 15987D9A DC0A486D         CDF93ACC 44328387 315D75E1 98C641A4 80CD86A1 B9E587E8         BE60E69C C928B2B9 C52172E4 13042E9B 23F10B0E 16E79763         C9B53DCF 4BA80A29 E3FB73C1 6B8E75B9 7EF363E2  FFA31F71         CF9DE538 4E71B81C 0AC4DFFE 0C10E64F"
    
    hexP = hexP.replace(" ", "")
    intP = int(hexP, 16)     
    return intP
    
    
#This is the subgroup of prime order Q, 160 bits. 
def getQ(group):
    if group == 1:
        hexQ = "F518AA87 81A8DF27 8ABA4E7D 64B7CB9D 49462353"
        
    else:
        if group == 2:
            hexQ = "801C0D34 C58D93FE 99717710 1F80535A 4738CEBC BF389A99         B36371EB"
        
    hexQ= hexQ.replace(" ", "")
    intQ = int(hexQ, 16)
        
    return intQ
    
    
#Returns the generator for a given group.
def getG(group):
    if group == 1:
        hexG = "A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F        D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213        160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1        909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A        D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24        855E6EEB 22B3B2E5"
        
    else:
            if group ==2:
                hexG = "AC4032EF 4F2D9AE3 9DF30B5C 8FFDAC50 6CDEBE7B 89998CAF        74866A08 CFE4FFE3 A6824A4E 10B9A6F0 DD921F01 A70C4AFA         AB739D77 00C29F52 C57DB17C 620A8652 BE5E9001 A8D66AD7         C1766910 1999024A F4D02727 5AC1348B B8A762D0 521BC98A         E2471504 22EA1ED4 09939D54 DA7460CD B5F6C6B2 50717CBE         F180EB34 118E98D1 19529A45 D6F83456 6E3025E3 16A330EF         BB77A86F 0C1AB15B 051AE3D4 28C8F8AC B70A8137 150B8EEB         10E183ED D19963DD D9E263E4 770589EF 6AA21E7F  5F2FF381         B539CCE3 409D13CD 566AFBB4 8D6C0191 81E1BCFE 94B30269         EDFE72FE 9B6AA4BD 7B5A0F1C 71CFFF4C 19C418E1 F6EC0179         81BC087F 2A7065B3 84B890D3 191F2BFA"
        
    hexG= hexG.replace(" ", "")
    intG = int(hexG, 16)
        
    return intG
    
    


#
#def main():
#
#    print miller_rabin(getG(1))
#    
#if __name__== "__main__":
#  main()
    
