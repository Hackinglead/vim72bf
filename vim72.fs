(* breaks <= vim7.2 encryption, translated from my C version.
   currently needs refactoring so that better observations can be made on how to exploit the xor *)
   (* http://www.woodmann.com/fravia/mike_zipattacks.htm *)
open System
open System.Text

(* http://fssnip.net/dS *)
let crctab = 
  let nextValue acc =
    if 0L <> (acc &&& 1L) then 0xedb88320L ^^^ (acc >>> 1) else acc >>> 1
  let rec iter k acc =
    if k = 0 then acc else iter (k-1) (nextValue acc)
  [| 0L .. 255L |] |> Array.map (iter 8)

let crc32 c b =
  crctab.[((int c ^^^ b) &&& 0xff)] ^^^ (c >>> 8)

//(* "of the ninety-six bits of internal state, eight bits of key0 affect key1; eight bits of key1 affect key2; and fourteen bits of key2 affect the output stream byte." *)
//let ``InitialKeyZero``= 0x12345678L
//let ``InitialKeyOne`` = 0x23456789L
//let ``InitialKeyTwo`` = 0x34567890L
//let ``KeyOneSecretK`` = 0x08088405L
//
//
//let ``all possible initial key0`` = 
//  [32..127] |> Seq.map (crc32 ``InitialKeyZero``)
//
//let ``all possible initial key1`` = 
//  ``all possible initial key0``
//  |> Seq.map (fun key0 -> ((key0 &&& 0xffL) + ``InitialKeyOne``) * ``KeyOneSecretK`` + 1L)
//
//let ``all possible initial key2`` = 
//  ``all possible initial key1``
//  |> Seq.map (fun key1 -> crc32 ``InitialKeyTwo`` (int key1 >>> 24))
//
//let x =
//  Seq.zip3 ``all possible initial key0`` ``all possible initial key1`` ``all possible initial key2``
//  
//(* All possible keys before updateKey is called for the first time *)
//let ``all possible initial keys`` = 
//  [| for (k1,k2,k3) in x do yield [| k1;k2;k3 |] |]


// will always return <255
let decryptByte (keys : int64 array) =
  
  let temp = uint16 keys.[2] ||| 2us
  int ((temp * (temp ^^^ 1us)) >>> 8) &&& 0xff

let updateKeys (keys : int64 array) c = 
  // let keys = [| ``InitialKeyZero``; ``InitialKeyOne``; ``InitialKeyTwo`` |]
  // let c = int '9' // 57
  let key0 = crc32 keys.[0] c

  let key1 = ((key0 &&& 0xffL) + keys.[1]) * 134775813L + 1L
  let key2 = crc32 keys.[2] (int key1 >>> 24)

  [| key0; key1; key2 |]

let zDecode keys (c : byte) =
  let nc = int c ^^^ (decryptByte keys)
  nc, updateKeys keys nc

let initKeys (passwd : string) = 
  let initialKeys = [| 305419896L; 591751049L; 878082192L |]
  let length = passwd.Length

  let rec loop n keys = 
    if n >= length then keys else
    loop (n+1) (updateKeys keys (int passwd.[n]))
  loop 0 initialKeys

let guessKey enc_bytes key =
  let cryptkey = initKeys key
  let len = enc_bytes |> Array.length 

  let rec loop n decodedStream keys =
    if n >= len then decodedStream 
    else
      let mx = zDecode keys enc_bytes.[n]
      loop (n+1) (fst mx :: decodedStream) (snd mx)
  loop 0 [] cryptkey

let toString =
  String.concat "" << Seq.map (string << char) 

let revMakeString =
  toString << List.rev  

// our guess.
let check password (s : string) = 
  if s.Contains "key" && s.Contains "wow"
  then Some (password,s) else None

// skip first 12 bytes of vimcrypt header.
let ciphertext = 
  @"C:\Users\david\Desktop\code\securityrelated_2\vim72\dogecrypt-b36f587051faafc444417eb10dd47b0f30a52a0b"
  |> IO.File.ReadAllBytes
  |> Seq.skip 12
  |> Seq.toArray

let wordlist = IO.File.ReadAllLines @"C:\Users\david\Desktop\code\securityrelated_2\vim72\darkc0de.lst"

let answer = 
  wordlist 
  |> Array.Parallel.choose (fun password ->
     guessKey ciphertext password
     |> revMakeString
     |> check password)
