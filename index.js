
import dotenv from "dotenv"

import {app} from './app.js'
dotenv.config({
    path: './.env'
})



const port = process.env.SERVER_PORT || 4000; 
app.listen(port, () => {
    console.log(`Listening on port ${port}`);
});