
pragma solidity >=0.4.22 <0.9.0;
import "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

contract PKtransfercancel {
    struct User
     {
         bytes public_key;
         string cancel_message;
         bool canceled;
         uint64 timestamp;
     }

     // Creating a mapping
     mapping (address => User) user_info;

     function new_user(bytes memory public_key) public {
        user_info[msg.sender]= User(public_key,"",false,0);
    }

    function get_user() public view returns (User memory) {
        return user_info[msg.sender];
    }

    function cancel_message(string memory message, bytes32 hash, uint8 v, bytes32 r, bytes32 s, uint64 time) public returns (bool) {
        User memory user = user_info[msg.sender];
        address signer = ECDSA.recover(hash, v,r,s);
        if (signer == msg.sender) {
          user_info[msg.sender]= User(user.public_key,message,true,time);
          return true;
        }
        user_info[msg.sender]= User(user.public_key,"",false,0);
        return false;
    }

}
