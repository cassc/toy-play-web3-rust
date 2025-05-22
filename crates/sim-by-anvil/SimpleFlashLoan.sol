pragma solidity 0.8.10;

import "./aave-v3-contracts/flashloan/base/FlashLoanSimpleReceiverBase.sol";
import "./aave-v3-contracts/interfaces/IPoolAddressesProvider.sol";
import "./aave-v3-contracts/dependencies/openzeppelin/contracts/IERC20.sol";

contract SimpleFlashLoan is FlashLoanSimpleReceiverBase {
    constructor(address _addressProvider)
        FlashLoanSimpleReceiverBase(IPoolAddressesProvider(_addressProvider)) {}

    function flashLoan(address _token, uint256 _amount) public {
        POOL.flashLoanSimple(
            address(this),
            _token,
            _amount,
            "",
            0
        );
    }

    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external override returns (bool) {
        uint256 balanceBeforeOperation = IERC20(asset).balanceOf(address(this));

        uint256 requiredRepayment = amount + premium;

        require(IERC20(asset).balanceOf(address(this)) >= requiredRepayment, "Insufficient balance to repay loan + premium");

        // Approve the POOL to pull the repayment amount
        IERC20(asset).approve(address(POOL), requiredRepayment);

        return true;
    }
}
