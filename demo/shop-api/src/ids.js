const { v4: uuidv4 } = require('uuid');

const newOrderId = () => `ord_${uuidv4()}`;
const requestId = () => uuidv4();

module.exports = { newOrderId, requestId };
