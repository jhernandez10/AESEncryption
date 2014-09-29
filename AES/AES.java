import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;

//All functions written by me unless otherwise stated in section header

public class AES {
	
	public static final boolean debugKey = false;
	
	public static void main(String[] args) throws IOException{
		int[][]key;
		
		key = readKeyFile(args[1]);
		ArrayList<int[][]> stuff = readDecrypt(args[2]);
		
		System.out.println("The plaintext is:");
		for(int[][] message: stuff)
			printMatrix(message);
		System.out.println("The CipherKey is:");
		printMatrix(key);
		System.out.println("The expanded key is:");
		int[][] expandedKey = expandKey(key);
		printMatrix(expandedKey);
		
		
		//encrypts lines if e is passed as an argument
		if(args[0].equals("e")){
			ArrayList<int[][]> lines = readText(args[2]);
			ArrayList<int[][]> encrypted = new ArrayList<int[][]>();
			for(int[][] message: lines ){
				int[][] done = encrypt(message,expandedKey);
				encrypted.add(done);
				printMatrix(done);
			}
			StringBuilder name = new StringBuilder(args[2]);
			name.append(".enc");
			writeToFile(name.toString(),encrypted);
		}
		
		if(args[0].equals("d")){
			ArrayList<int[][]> decrypted = new ArrayList<int[][]>();
			for(int[][] message: stuff){
				int[][] done = decrypt(message,expandedKey);
				decrypted.add(done);
				printMatrix(done);
			}
			StringBuilder name = new StringBuilder(args[2]);
			name.append(".dec");
			writeToFile(name.toString(),decrypted);
		}
		
	}
	
	/******************************************************************
	 * 
	 * Section for IO functions
	 * @throws IOException 
	 * 
	 *****************************************************************/
	public static void writeToFile(String fileName, ArrayList<int[][]> messages) throws IOException{
		BufferedWriter out = new BufferedWriter(new FileWriter(fileName));
		for(int[][] message: messages){
			for(int col = 0; col < 4; col++){
				for(int row = 0; row < 4; row++){
					out.write(message[row][col]);
				}
			}
			out.newLine();
		}
		out.close();
	}
	
	//function to read in the key file
	public static int[][] readKeyFile(String keyFile) throws IOException {
		String keyLine = null;
		BufferedReader in = null;
		int[][] key = new int[4][8];
		
		try {
			in = new BufferedReader(new FileReader(keyFile));
			keyLine = in.readLine();
		}
		catch (FileNotFoundException e) {
			System.out.println(e);
		}finally{
			in.close();
		}
		
		char[] values = keyLine.toCharArray();
		//send all to lower case
		int[] hexValues = convertCharArray(values);
		
		key = format(hexValues,8);
		
		return key;
	}
	
	//reads in text to encode
	public static ArrayList<int[][]> readText(String plainText) throws IOException{
		ArrayList<int[][]> lines = new ArrayList<int[][]>();
		BufferedReader in = null;
		
		try {
			in = new BufferedReader(new FileReader(plainText));
			String temp = in.readLine();
			while(temp != null){
				int[] step1 = convertCharArray(temp.toCharArray());
				if(step1[0] != -1  && step1.length == 16){
					lines.add(format(step1,4));
				}
				temp = in.readLine();
			}
			
		}
		catch (FileNotFoundException e) {
			System.out.println(e);
		}finally{
			in.close();
		}
		
		lines.trimToSize();
		return lines;
	}
	
	public static ArrayList<int[][]> readDecrypt(String fileName) throws IOException{
		ArrayList<int[][]> lines = new ArrayList<int[][]>();
		BufferedReader in = null;
		
		try {
			in = new BufferedReader(new FileReader(fileName));
			int bytes = 0;
			int value = in.read();
			int[] message = new int[16];
			while(value != -1){
				message[bytes] = value;
				bytes++;
				if(bytes == 16){
					lines.add(format(message,4));
					bytes = 0;
					message = new int[16];
				}
				value = in.read();
			}	
		}
		catch (FileNotFoundException e) {
			System.out.println(e);
		}finally{
			in.close();
		}
		
		lines.trimToSize();
		return lines;
	}
	
	//cast ArrayList Object[] to int[]
	public static int[] convert(Object[] values){
		System.out.println(values.length);
		int[] temp = new int[values.length];
		int position = 0;
		for(Object i: values){
			temp[position] =(int)i;
		}
		return temp;
	}
	
	//converts a char array to an array of hex values
	public static int[] convertCharArray(char[] values){
		int[] hexValues = new int [(values.length)/2];
		
		int position = 0;
		for(int i = 0; i < values.length; i+=2){
			int temp = convertChartoHex(values[i],values[i+1]);
			if(temp != -1){
				hexValues[position] = temp;
				position++;
			}else{
				int[] wrong = {-1};
				return wrong;
			}
			
		}
		
		return hexValues;
	}
	
	//converts a character from its' value to a hex value
	public static int convertChartoHex(char one, char two){
		int hex = 0x00;
		int temp1;
		int temp2;
		
		boolean bone =validHex(one);
		boolean btwo = validHex(two);
		if(bone && btwo == false){
			return -1;
		}
		
		if(bone && Character.isAlphabetic(one)){
			temp1 = ((one - 65 + 10) << 4) & 0xf0;
		}else{
			temp1 = ((one - 48) << 4) & 0xf0;
		}
		
		if(btwo && Character.isAlphabetic(two)){
			temp2 = (two - 65 + 10) & 0x0f;
		}else{
			temp2 = (two - 48) & 0x0f;
		}
		
		hex = temp1 | temp2;
		
		return hex;
	}
	

	//returns true if it something between 0 and f
	public static boolean validHex(char test){
		return (Character.digit(test, 10) <= 255);
	}
	
	public static int[][] format(int[] hexValues, int cols){
		int[][] values = new int[4][cols];
		int position = 0;		
		for(int col = 0; col < cols; col++){
			for(int row = 0; row < 4; row++){
				values[row][col] = hexValues[position];
				position++;
			}
		}
		
		return values;
	}
	
	
	/******************************************************************
	 * 
	 * End section for IO functions
	 * 
	 *****************************************************************/
	
	/******************************************************************
	 * 
	 * Section for encrypting and decrypting functions
	 * 
	 *****************************************************************/
	public static int[][] encrypt(int[][] encrypt, int[][] key){
		int[][] message = encrypt;
		int[][] expanded = key;
		
		int round = 0;
		message = addRoundKey(message,expanded,round);
		round++;
		
		for(int i = 0; i < 13; i ++){
			message = subBytes(message,0);
			message = shiftRows(message, 0);
			message = mixColumns(message,0);
			message = addRoundKey(message,expanded,round);
			round++;
		}
		
		message = subBytes(message,0);
		message = shiftRows(message,0);
		message = addRoundKey(message,expanded,round);
		round++;
		
		return message;
	}
	
	public static int[][] decrypt(int[][] encrypted, int[][] key){
		int[][] message = encrypted;
		int[][] expanded = key;
		
		int round;
		round = 14;
		message = addRoundKey(message,expanded,round);
		round--;
		for(int i = 0; i < 13; i ++){
			message = shiftRows(message, 1);
			message = subBytes(message,1);
			message = addRoundKey(message,expanded,round);
			round--;
			message = mixColumns(message,1);
		}
						
	    
		message = shiftRows(message,1);
		message = subBytes(message,1);
		message = addRoundKey(message,expanded,round);
		round--;
		
		return message;
	}
	
	/******************************************************************
	 * 
	 * End section for encrypting and decrypting functions
	 * 
	 *****************************************************************/
	
	
	/******************************************************************
	 * 
	 * Section for expanding the key
	 * 
	 *****************************************************************/
	
	
	//function to create the expanded key for the encryption
	public static int[][] expandKey(int[][] key){
		int size = 4*15;  //hard code 256 bit key
		int[][] expanded = new int[4][size];
		int bytesLeft = 240;
		
		//copy the key into expanded
		for(int i =0; i < key.length; i++){
			for(int j = 0; j < key[0].length; j++){
				expanded[i][j] = key[i][j];
			}
		}
		
		bytesLeft = bytesLeft -32;
		
		//rcon starts at 1
		int rcon = 1;
		int col = 8;
		
		//broken down into two 16 byte sections
		while(bytesLeft != 0){
			//first 16 bytes
			int [] temp = keyCore(expanded,rcon,col);
			rcon++;
			xOR(expanded,temp,col);
			col += 4;
			bytesLeft -= 16;
			
			//prints out the expanded key after every first 16 byte step in cycle
			if(debugKey){
			  System.out.println();
			  printMatrix(expanded);
			  System.out.println();
			}
			
			//second 16 bytes has to check to make sure it is still needed
			if(bytesLeft!=0){
				temp = copyCol(expanded,col -1);
				
				//prints the col that was copied
				if(debugKey){
				  System.out.println(Integer.toString(col -1));
				  for(int i: temp){
					  System.out.printf("%s ",Integer.toHexString(i));
				  }
				  System.out.println();
				}
				
				temp = sSub(temp,0);
				
				//prints the sSub array
				if(debugKey){
				  for(int i: temp){
					  System.out.printf("%s ",Integer.toHexString(i));
				  }
				  System.out.println();
				}
				xOR(expanded,temp,col);
				col += 4;
				bytesLeft -= 16;
			}
		}
		
		return expanded;
	}
	
	//performs xor action in key expansion and changes the key to appropriate key
	public static void xOR(int[][] expand, int[] key, int col){
		int[] tempK = key;
		for(int i = 0; i < 4; i++){
			for(int row = 0; row < 4; row++){
				int temp = expand[row][col - 8 + i]^tempK[row];
				expand[row][i+col] = temp;
				tempK[row] = temp;
			}
		}
	}
	
	
	//function to create array used in first step in key expansion for a round
	public static int[] keyCore(int [][] expand, int round, int col){
		int[] step = new int[4]; 
		int temp = col -1;  //core functions only occur at the start of each 32byte set
		
		//rotwood portion
		for(int i = 0; i<4;i++){
			if(i != 3){
				step[i] = expand[i+1][temp]; //shift bottom three up
			}else{
				step[i] = expand[0][temp];//move top of col to bottom
			}
		}
		
		//separated two parts for clarity in debugging turn into one step later
		//sSub portion
		step = sSub(step,0);
		
		//adding in Rcon
		step[0] = step[0]^getRcon(round);
		return step;
	}
	
	/******************************************************************
	 * 
	 *  End section for expanding the key
	 * 
	 *****************************************************************/
	/******************************************************************
	 * 
	 * Section for functions during rounds of protocol
	 *
	 *****************************************************************/
	//This method performs an arbitray round of add round
	public static int[][] addRoundKey(int[][] message,int[][] keys, int round){
		int position;
		int[] key;
		int[][] temp = message;
		
		for(int col = 0; col < 4; col++){
			position = (round * 4) + col;
			key  = copyCol(keys,position); 
			for(int row = 0; row < 4; row++){
				message[row][col] = message[row][col]^key[row];
			}
		}
		return temp;
	}
	
	//function that substitutes an entire 4x4 array either normally or inverse
	public static int[][] subBytes(int[][] message, int inverse){
		int[][] temp = message;
		
		if(inverse == 0){
			for(int col =0; col < 4; col++){
				for(int row = 0; row < 4; row++){
					temp[row][col] = getSbox(temp[row][col],inverse);
				}
			}
		}else{
			for(int col =0; col < 4; col++){
				for(int row = 0; row < 4; row++){
					temp[row][col] = getSbox(temp[row][col],inverse);
				}
			}
		}
		
		return message;
	}
	
	//shifts the rows left by a byte a number of times based on the protocol
	//for inverse pass in value != 0
	public static int[][] shiftRows(int[][] message,int inverse){
		int[][] temp = message;
		
		if(inverse == 0){
			//starts at 1 because we don't shift the first row
			for(int row = 1; row < 4; row++){
				if(row == 1){
					temp = rotateOnce(temp,row,0);
				}else if(row == 2){
					temp = rotateOnce(temp,row,0);
					temp = rotateOnce(temp,row,0);
				}else if(row == 3){
					temp = rotateOnce(temp,row,0);
					temp = rotateOnce(temp,row,0);
					temp = rotateOnce(temp,row,0);
				}
			}
		}else{
			//starts at 1 because we don't shift the first row
			for(int row = 1; row < 4; row++){
				if(row == 1){
					temp = rotateOnce(temp,row,1);
				}else if(row == 2){
					temp = rotateOnce(temp,row,1);
					temp = rotateOnce(temp,row,1);
				}else if(row == 3){
					temp = rotateOnce(temp,row,1);
					temp = rotateOnce(temp,row,1);
					temp = rotateOnce(temp,row,1);
				}
			}
		}
		
		return temp;
	}
		
	public static int[][] mixColumns(int[][] message, int direction){
		int[][] temp = message;
		if(direction == 0){
			for(int col = 0; col < 4; col++){
				temp = mixColumn2(temp,col);
			}
		}else{
			for(int col = 0; col < 4; col++){
				temp = invMixColumn2(temp,col);
			}
		}
		
		return temp;
	}
	
	
	/******************************************************************
	 * 
	 * End section for functions during rounds of protocol
	 * 
	 *****************************************************************/
	/******************************************************************
	 *  http://www.cs.utexas.edu/~byoung/cs361/mixColumns-cheat-sheet
	 *  Section for  B Youngs' implementation of MixColumns
	 *  edited only so it can work with my program
	 *****************************************************************/
	private static int mul (int a, byte b) {
		int inda = (a < 0) ? (a + 256) : a;
		int indb = (b < 0) ? (b + 256) : b;

		if ( (a != 0) && (b != 0) ) {
		    int index = (LogTable[inda] + LogTable[indb]);
		    byte val = (byte)(AlogTable[ index % 255 ] );
		    return val;
		}
		else 
		    return 0;
	    } // mul

	    // In the following two methods, the input c is the column number in
	    // your evolving state matrix st (which originally contained 
	    // the plaintext input but is being modified).  Notice that the state here is defined as an
	    // array of bytes.  If your state is an array of integers, you'll have
	    // to make adjustments. 

	    public static int[][] mixColumn2 (int[][] st, int c) {
		// This is another alternate version of mixColumn, using the 
		// logtables to do the computation.
	    int[][] temp = st;
		
		byte a[] = new byte[4];
		
		// note that a is just a copy of st[.][c]
		for (int i = 0; i < 4; i++) 
		    a[i] =(byte) st[i][c];
		
		// This is exactly the same as mixColumns1, if 
		// the mul columns somehow match the b columns there.
		st[0][c] = ((mul(2,a[0]) ^ a[2] ^ a[3] ^ mul(3,a[1]))) & 0xff;
		st[1][c] = ((mul(2,a[1]) ^ a[3] ^ a[0] ^ mul(3,a[2]))) & 0xff;
		st[2][c] = ((mul(2,a[2]) ^ a[0] ^ a[1] ^ mul(3,a[3]))) & 0xff;
		st[3][c] = ((mul(2,a[3]) ^ a[1] ^ a[2] ^ mul(3,a[0]))) & 0xff;
		
		return temp;
	    } // mixColumn2

	    public static int[][] invMixColumn2 (int[][] st,int c) {
	    int[][] temp = st;
		byte a[] = new byte[4];
		
		// note that a is just a copy of st[.][c]
		for (int i = 0; i < 4; i++) 
		    a[i] = (byte)st[i][c];
		
		st[0][c] = ((mul(0xE,a[0]) ^ mul(0xB,a[1]) ^ mul(0xD, a[2]) ^ mul(0x9,a[3]))) &0xff;
		st[1][c] = ((mul(0xE,a[1]) ^ mul(0xB,a[2]) ^ mul(0xD, a[3]) ^ mul(0x9,a[0]))) &0xff;
		st[2][c] = ((mul(0xE,a[2]) ^ mul(0xB,a[3]) ^ mul(0xD, a[0]) ^ mul(0x9,a[1]))) &0xff;
		st[3][c] = ((mul(0xE,a[3]) ^ mul(0xB,a[0]) ^ mul(0xD, a[1]) ^ mul(0x9,a[2]))) &0xff;
		
		return temp;
	     } // invMixColumn2
	
	
	/******************************************************************
	 * 
	 *  End section for B Youngs' implementation of MixColumns
	 * 
	 *****************************************************************/
	
	/******************************************************************
	 * 
	 *  Section for accessing static array constants
	 * 
	 *****************************************************************/
	//function to automate sbox substitution for a single column
	public static int[] sSub(int[] col, int box){
		int[] temp = new int[4];
		for(int i = 0; i < 4; i++){
			temp[i] = getSbox(col[i],box);
		}
		
		return temp;
	}
	
	//function to get value from sbox(0) or sboxInverse(1)
	public static int getSbox(int value, int box){
		int row = (value & 0xf0) >> 4;
		int col = value & 0x0f;
		
		
		if(box ==0){
			return sbox[row][col];
		}
		
		return sboxInverse[row][col];
	}
	
	public static int getRcon(int index) {
		if (index < 0 || index > 255) {
			return -1;
		}
		return (rcon[index]);
	}
	
	/******************************************************************
	 * 
	 *  End section for accessing static array constants
	 * 
	 *****************************************************************/
	/******************************************************************
	 * 
	 *  Section for static array constants and helper functions
	 * 
	 *****************************************************************/
	//copies a specified column from a 2d array
	public static int[] copyCol(int[][] group, int col){
		int[] temp = new int[4];
			
		for(int i = 0; i < 4; i++){
			temp[i] = group[i][col];
		}
			
		return temp;
		}
	
	
	//rotates a given row to the left by one or right depending on value passed in
	public static int[][] rotateOnce(int[][] message, int row, int direction){
		int[][] temp = message;
		
		if(direction == 0){
			int first = 0;
			for(int col = 0; col < 4; col++){
				if(col == 0){
					first = temp[row][col];  //save value in first col
					temp[row][col] = temp[row][col + 1];
				}else if(col == 3){
					temp[row][col] = first;  //move value to last col
				}else{
					temp[row][col] = temp[row][col + 1]; //just shift
				}			
			}		
		}else{
			int last = 0;
			for(int col = 3; col >= 0; col--){
				if(col == 3){
					last = temp[row][col];  //save value in last col
					temp[row][col] = temp[row][col -1];
				}else if(col == 0){
					temp[row][col] = last;  //move value to first col
				}else{
					temp[row][col] = temp[row][col - 1]; //just shift
				}			
			}		
		}
		
		return temp;
	}
	
	//used to print out to console and check values
	public static void printMatrix(int[][] matrix){
		for(int[] i: matrix){
			for(int j: i){
				String temp =Integer.toHexString(j);
				if(!temp.equals("0") && temp.length() != 1){
					System.out.printf("%s ",temp);
				}else{
					System.out.printf("0%s ",temp);
				}
			}
			System.out.println();
		}
		System.out.println();
	}
	
	//value for Sbox
	public static final int[][] sbox = new int[][] 
			{ 	
				{ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },
				{ 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 },
				{ 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 },
				{ 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 },
				{ 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 },
				{ 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf },
				{ 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 },
				{ 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 },
				{ 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 },
				{ 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb },
				{ 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 },
				{ 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 },
				{ 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a },
				{ 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e },
				{ 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf },
				{ 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }
			};
	
	
	//value for the inverse of the sbox
	public static final int[][] sboxInverse = new int[][]
			{
				{ 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB },
				{ 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB },
				{ 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E },
				{ 0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25 },
				{ 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92 },
				{ 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84 },
				{ 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06 },
				{ 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B },
				{ 0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73 },
				{ 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E },
				{ 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B },
				{ 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4 },
				{ 0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F },
				{ 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF },
				{ 0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61 },
				{ 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D }
			};
	
	private static final int[] rcon = new int[] 
			{
				0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
				0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
				0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
				0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
				0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
				0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
				0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
				0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
				0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
				0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
				0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
				0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
				0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
				0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
				0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
				0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d 
			};
	
	final static int[] LogTable = {
		0,   0,  25,   1,  50,   2,  26, 198,  75, 199,  27, 104,  51, 238, 223,   3, 
		100,   4, 224,  14,  52, 141, 129, 239,  76, 113,   8, 200, 248, 105,  28, 193, 
		125, 194,  29, 181, 249, 185,  39, 106,  77, 228, 166, 114, 154, 201,   9, 120, 
		101,  47, 138,   5,  33,  15, 225,  36,  18, 240, 130,  69,  53, 147, 218, 142, 
		150, 143, 219, 189,  54, 208, 206, 148,  19,  92, 210, 241,  64,  70, 131,  56, 
		102, 221, 253,  48, 191,   6, 139,  98, 179,  37, 226, 152,  34, 136, 145,  16, 
		126, 110,  72, 195, 163, 182,  30,  66,  58, 107,  40,  84, 250, 133,  61, 186, 
		43, 121,  10,  21, 155, 159,  94, 202,  78, 212, 172, 229, 243, 115, 167,  87, 
		175,  88, 168,  80, 244, 234, 214, 116,  79, 174, 233, 213, 231, 230, 173, 232, 
		44, 215, 117, 122, 235,  22,  11, 245,  89, 203,  95, 176, 156, 169,  81, 160, 
		127,  12, 246, 111,  23, 196,  73, 236, 216,  67,  31,  45, 164, 118, 123, 183, 
		204, 187,  62,  90, 251,  96, 177, 134,  59,  82, 161, 108, 170,  85,  41, 157, 
		151, 178, 135, 144,  97, 190, 220, 252, 188, 149, 207, 205,  55,  63,  91, 209, 
		83,  57, 132,  60,  65, 162, 109,  71,  20,  42, 158,  93,  86, 242, 211, 171, 
		68,  17, 146, 217,  35,  32,  46, 137, 180, 124, 184,  38, 119, 153, 227, 165, 
		103,  74, 237, 222, 197,  49, 254,  24,  13,  99, 140, 128, 192, 247, 112,   7};
	
	final static int[] AlogTable = {
		1,   3,   5,  15,  17,  51,  85, 255,  26,  46, 114, 150, 161, 248,  19,  53, 
		95, 225,  56,  72, 216, 115, 149, 164, 247,   2,   6,  10,  30,  34, 102, 170, 
		229,  52,  92, 228,  55,  89, 235,  38, 106, 190, 217, 112, 144, 171, 230,  49, 
		83, 245,   4,  12,  20,  60,  68, 204,  79, 209, 104, 184, 211, 110, 178, 205, 
		76, 212, 103, 169, 224,  59,  77, 215,  98, 166, 241,   8,  24,  40, 120, 136, 
		131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206,  73, 219, 118, 154, 
		181, 196,  87, 249,  16,  48,  80, 240,  11,  29,  39, 105, 187, 214,  97, 163, 
		254,  25,  43, 125, 135, 146, 173, 236,  47, 113, 147, 174, 233,  32,  96, 160, 
		251,  22,  58,  78, 210, 109, 183, 194,  93, 231,  50,  86, 250,  21,  63,  65, 
		195,  94, 226,  61,  71, 201,  64, 192,  91, 237,  44, 116, 156, 191, 218, 117, 
		159, 186, 213, 100, 172, 239,  42, 126, 130, 157, 188, 223, 122, 142, 137, 128, 
		155, 182, 193,  88, 232,  35, 101, 175, 234,  37, 111, 177, 200,  67, 197,  84, 
		252,  31,  33,  99, 165, 244,   7,   9,  27,  45, 119, 153, 176, 203,  70, 202, 
		69, 207,  74, 222, 121, 139, 134, 145, 168, 227,  62,  66, 198,  81, 243,  14, 
		18,  54,  90, 238,  41, 123, 141, 140, 143, 138, 133, 148, 167, 242,  13,  23, 
		57,  75, 221, 124, 132, 151, 162, 253,  28,  36, 108, 180, 199,  82, 246,   1};
	
	/*public static int[][] key = new int[][]
			{
				{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
				{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
				{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
				{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}
		};
	
	public static int[][] message = new int [][]
			{
				{0x00,0x44,0x88,0xCC},
				{0x11,0x55,0x99,0xDD},
				{0x22,0x66,0xAA,0xEE},
				{0x33,0x77,0xBB,0xFF}
			};*/
	
	/******************************************************************
	 * 
	 *  End Section for static array constants and miscellaneous
	 * 
	 *****************************************************************/
	
}
