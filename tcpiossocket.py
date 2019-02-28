#Python IOS chat server

import socket, select, json, uuid, hashlib, time, logging, threading, random


###Constants

message_type_request = "Request"
message_type_response = "Response"
purpose_verification = "Verification"
purpose_chat_message = "ChatMessage"
purpose_user_num = "UserNum"
purpose_connect_chat_room = "ConnectChatRoom"
purpose_leave_chat_room = "LeaveChatRoom"
purpose_cancel_chat_room_connection = "CancelChatRoomConnection"
purpose_change_user_name = "ChangeUserName"
purpose_server_has_no_room = "ServerHasNoRoom"
purpose_utility_get_all_sockets = "UtilityGetAllSockets"
purpose_report_user = "ReportUser"
purpose_block_user = "BlockUser"
socket_connection_state_in_lobby = "InLobby"
socket_connection_state_matching = "Matching"
socket_connection_state_in_chatroom = "InChatRoom"

verification_code = "your verification code"

###


###Verification funcs

def send_verification_question(sock):
    user_id = sock.user_id
    jsonDict = { "type": message_type_response, "purpose": purpose_verification, "id": user_id, "status": "Required" }
    jsonStr = json.JSONEncoder().encode(jsonDict)
    json_data = jsonStr.encode("utf-8")
    send_message_to_socket(sock.fd, json_data)
    logging.info("Verification request was sent - id sent: {}".format(user_id))

def send_verification_completed(sock):
    user_id = sock.user_id
    jsonDict = { "type": message_type_response, "purpose": purpose_verification, "id": user_id, "status": "Completed" }
    jsonStr = json.JSONEncoder().encode(jsonDict)
    json_data = jsonStr.encode("utf-8")
    send_message_to_socket(sock.fd, json_data)

def send_server_has_no_room(sock):
    user_id = sock.user_id
    jsonDict = { "type": message_type_response, "purpose": purpose_server_has_no_room }
    jsonStr = json.JSONEncoder().encode(jsonDict)
    json_data = jsonStr.encode("utf-8")
    formatted_data = add_start_end_indicator(json_data)

    try:
        sock.conn.sendall(formatted_data)
    except:
        return
    logging.info("Server has no room was sent - id sent: {}".format(user_id))

    thread = threading.Thread(target = closeSocketConnection, args=(sock.conn, 3,))
    thread.start()

def closeSocketConnection(conn, delay):
    time.sleep(delay)
    conn.close()

#return True if verified, return False otherwise
def process_received_verification_data(sock, jsonStr):
    user_id = sock.user_id

    jsonDict = json.JSONDecoder().decode(jsonStr)

    msgType = jsonDict.get("type")
    purpose = jsonDict.get("purpose")

    if msgType == message_type_request and purpose == purpose_verification:
        code = jsonDict.get("code")
        valid_code = user_id+verification_code
        hash_code = hashlib.sha224()
        hash_code.update(valid_code.encode("utf-8"))
        logging.info("hash code comparison: {} - {}".format(hash_code.hexdigest(), code))
        if code == hash_code.hexdigest():
            #verification was successful
            sock.verified = True
            send_verification_completed(sock)
            return True

    return False

###


###JSON Creation Funcs

#Utility func
def create_get_all_sockets_json_data():
    socket_arr = []
    for key in all_sockets:
        socket_arr.append(all_sockets[key].address)
    jsonDict = { "type": message_type_response, "purpose": purpose_utility_get_all_sockets, "sockets": socket_arr }
    jsonStr = json.JSONEncoder().encode(jsonDict)
    jsonData = jsonStr.encode("utf-8")
    return jsonData

def create_chat_room_message_json_data(message, sender):
    jsonDict = { "type": message_type_response, "purpose": purpose_chat_message, "message": message, "sender": sender }
    jsonStr = json.JSONEncoder().encode(jsonDict)
    jsonData = jsonStr.encode("utf-8")
    return jsonData

def create_user_num_json_data(user_num):
    jsonDict = { "type": message_type_response, "purpose": purpose_user_num, "number": user_num }
    jsonStr = json.JSONEncoder().encode(jsonDict)
    jsonData = jsonStr.encode("utf-8")
    return jsonData

def create_join_chat_room_json_data(is_matching_socket_found, user_name, user_id):
    if is_matching_socket_found == False :
        #reason code 1 = no matching socket found. switching to matching state
        jsonDict = { "type": message_type_response, "purpose": purpose_connect_chat_room, "userName": user_name, "userId": user_id, "status": "Failure", "reason": 1 }
        jsonStr = json.JSONEncoder().encode(jsonDict)
        jsonData = jsonStr.encode("utf-8")
        return jsonData
    else:
        jsonDict = { "type": message_type_response, "purpose": purpose_connect_chat_room, "userName": user_name, "userId": user_id, "status": "Success" }
        jsonStr = json.JSONEncoder().encode(jsonDict)
        jsonData = jsonStr.encode("utf-8")
        return jsonData

def create_leave_chat_room_json_data(did_my_self_leave, isValidRequest):
    if isValidRequest:
        jsonDict = { "type": message_type_response, "purpose": purpose_leave_chat_room, "status": "Success", "didMySelfLeave": did_my_self_leave }
        jsonStr = json.JSONEncoder().encode(jsonDict)
        jsonData = jsonStr.encode("utf-8")
        return jsonData
    else:
        jsonDict = { "type": message_type_response, "purpose": purpose_leave_chat_room, "status": "Failure", "didMySelfLeave": did_my_self_leave }
        jsonStr = json.JSONEncoder().encode(jsonDict)
        jsonData = jsonStr.encode("utf-8")
        return jsonData

def create_cancel_chat_room_connection_json_data():
    jsonDict = { "type": message_type_response, "purpose": purpose_cancel_chat_room_connection }
    jsonStr = json.JSONEncoder().encode(jsonDict)
    jsonData = jsonStr.encode("utf-8")
    return jsonData
    
###


###Chat room funcs

def match_socket_for_chatroom(lock, socket):
    #make the current socket's state to be waiting so other sockets can find
    #logging.info("putting socket to waiting state: {}".format(socket.address))
    socket.connection_state = socket_connection_state_matching
    
    thread = threading.Thread(target = match_socket_background_thread_task, args=(lock, socket,))
    thread.start()
    

def match_socket_background_thread_task(lock, socket):

    #wait for 2 secs until collect waiting sockets
    time.sleep(2)

    #check if the current socket is still in waiting state, if not, cancel the operation
    if socket.connection_state != socket_connection_state_matching:
        #logging.info("socket is not in matching state, cancel the operation")
        return
    
    waiting_sockets = []

    for key, socket_found in all_sockets.items():

        if socket_found == socket:
                    #skip my socket to avoid connecting to myself
                    continue

        if socket_found.user_id in socket.user_blocked:
            #This user is blocked, so dont match with this person
            logging.info("User is blocked, so don't match -{}".format(socket_found.user_id))
            continue
        
        conn_state = socket_found.connection_state
        if conn_state == socket_connection_state_matching:
            waiting_sockets.append(socket_found)
    
    logging.info("num of waiting sockets: {}".format(len(waiting_sockets)))

    if len(waiting_sockets) == 0:
        #if no waiting socket found, return
        return

    #randomly select a waiting socket from array
    lock.acquire()
    index = random.randint(0, len(waiting_sockets)-1)
    matching_socket = waiting_sockets[index]

    sock1 = matching_socket
    sock2 = socket
            
    room_num = str(uuid.uuid4())
    sock1.room_num = room_num
    sock2.room_num = room_num
    sock1.connection_state = socket_connection_state_in_chatroom
    sock2.connection_state = socket_connection_state_in_chatroom
    
    all_chat_rooms[room_num] = (sock1, sock2)
    lock.release()

    #logging.info("Matching sockets found - send push notification")
    #send matching message to the sockets
    json_data1 = create_join_chat_room_json_data(True, sock2.user_name, sock2.user_id)
    json_data2 = create_join_chat_room_json_data(True, sock1.user_name, sock1.user_id)
    send_message_to_socket(sock1.fd, json_data1)
    send_message_to_socket(sock2.fd, json_data2)
    

def cancel_chat_room_connection(sock):
    #logging.info("Current sock's connection state: {}".format(sock.connection_state))
    if sock.connection_state == socket_connection_state_in_chatroom:
        #if sock was already connected to other user, ignore this operation
        return
    
    #cancel the ongoing request for chat room connection from the sock
    sock.connection_state = socket_connection_state_in_lobby
    json_data = create_cancel_chat_room_connection_json_data()
    send_message_to_socket(sock.fd, json_data)

def leave_chat_room(sock):
    #get the sock out of the chat room and the corresponding other user socket as well
    room_num = sock.room_num
    socketTuple = all_chat_rooms.get(room_num)
    if socketTuple == None:
        #logging.info("such room doesn't exist - cancel the operation (leave chat room)")
        #will send failure status here
        sock_who_left = create_leave_chat_room_json_data(True, False)
        send_message_to_socket(sock.fd, sock_who_left)
        return
    receiver_fd = socketTuple[0].fd if socketTuple[1].fd == sock.fd else socketTuple[1].fd

    remove_room_from_all_chat_room(room_num)

    #will notify other socket that they have been removed from the room
    sock_who_left = create_leave_chat_room_json_data(True, True)
    sock_who_getting_notified = create_leave_chat_room_json_data(False, True)

    send_message_to_socket(receiver_fd, sock_who_getting_notified)
    send_message_to_socket(sock.fd, sock_who_left)

###


###Global array related funcs

def remove_room_from_all_chat_room(room_num):
    #remove the room from the dict and the assign a empty room num string of the sockets in it to notify the sockets are not in the room
    socket_tuple = all_chat_rooms.get(room_num)
    if socket_tuple == None or room_num == "":
        #such room doesn't exist, cancel the operation
        return

    socket_tuple[0].room_num = ""
    socket_tuple[1].room_num = ""
    del all_chat_rooms[room_num]

def remove_socket_from_server(poll_object, sock):
    if sock.fd in all_sockets:
        #remove socket from the server and close the socket connection
        del all_sockets[sock.fd]
        leave_chat_room(sock)
        #remove_room_from_all_chat_room(sock.room_num) #make sure the sock is removed from room as well
        poll_object.unregister(sock.fd)
        sock.conn.close()
    
###

def get_connected_user_number():
    num_of_users = len(all_sockets) - 1
    return num_of_users

def encode_message_json(message, sender):
    logid = str(uuid.uuid4())
    jsonDict = { "type": message_type_response, "sender": sender, "message": message, "logid": logid }
    jsonStr = json.JSONEncoder().encode(jsonDict)
    jsonData = jsonStr.encode("utf-8")
    return jsonData

def decode_message_json(jsonStr):
    #logging.info("jsonStr: {}".format(jsonStr.encode("utf-8")))
    jsonDict = json.JSONDecoder().decode(jsonStr)
    msgType = jsonDict["type"]

    purpose = jsonDict.get("purpose", "")
    sender = ""
    message = ""
    logid = ""
        
    if msgType == message_type_response:
        sender = jsonDict["sender"]
        message = jsonDict["message"]
        logid = jsonDict["logid"]
    elif msgType == message_type_request:
        message = jsonDict.get("message", "")
        if purpose == purpose_connect_chat_room:
            sender = jsonDict.get("sender")
    else:
        #msgType wasn't passed to. error
        logging.info("Message Type was not correctly sent")
        purpose = None

    #logging.info("MSG type: {}, purpose: {}, message: {}".format(msgType, purpose, message.encode("utf-8")))
    
    return (purpose, sender, message, logid)

def decode_user_name_change_message_json(jsonStr):
    jsonDict = json.JSONDecoder().decode(jsonStr)
    user_name = jsonDict.get("name", "")
    return user_name

def decode_report_user_message_json(jsonStr):
    jsonDict = json.JSONDecoder().decode(jsonStr)
    reporter = jsonDict.get("reporter", "")
    user_id = jsonDict.get("id", "")
    user_name = jsonDict.get("user", "")
    details = jsonDict.get("details", "")
    return (reporter, user_id, user_name, details)

def decode_block_user_message_json(jsonStr):
    jsonDict = json.JSONDecoder().decode(jsonStr)
    user = jsonDict.get("user", "")
    return user

def get_valid_data(data):


    data_str = None
    try:
        data_str = data.decode("utf-8")
    except:
        data_str = None

    if data_str == None:
        logging.info("Data received could not be decoded")
        return ""

    start_index = data_str.find("<--")

    if start_index == -1:
        logging.info("start indicator was not found")
        return ""

    end_index = data_str[start_index+1:].find("-->")

    if end_index == -1:
        logging.info("end indicator was not found")
        return ""

    end_index += start_index+1

    valid_str = data_str[start_index+3: end_index]
    return valid_str

def add_start_end_indicator(str_data):
    start = b"<--"
    end = b"-->"
    return start+str_data+end

def observe_events(poll_object):
    while True:
        for fd, event in poll_object.poll():
            yield fd, event

def send_message_to_socket(fd, data):
    sock = all_sockets.get(fd)
    if sock == None:
        logging.info("Can't send a message to unregistered socket")
        return
    conn = sock.conn
    formatted_data = add_start_end_indicator(data)

    try:
        conn.sendall(formatted_data)
    except e:
        logging.info("Error found while sending message: {}".format(e))

def broadcast_message(data, exceptions=[]):
    #broadcasting the message data to all connections excluding the exceptions
    logging.info("Broadingcasting message data: {}".format(data))
    for fd in all_sockets:
        if fd in exceptions:
            #exceptions are not included
            continue
        if all_sockets[fd].verified == False:
            #if the user hasn't been verified, don't send
            continue
        conn = all_sockets[fd].conn
        formatted_data = add_start_end_indicator(data)
        try:
            conn.sendall(formatted_data)
        except:
            return

def get_socket_with_fd(fd):
    for sock in all_sockets:
        if sock.fd == fd:
            return sock
    return None

def get_other_user_in_chat_room(sock):
    room = all_chat_rooms.get(sock.room_num, "")

    if room == "":
        return None
    
    if room[0] == sock:
        return room[1]
    else:
        return room[0]

def get_sock_with_user_id(user_id):

    for key, socket in all_sockets.items():
        if socket.user_id == user_id:
            return socket
        
    return None

### socket connection class

class SocketConnection:

    def __init__(self, fileno, conn, address, connection_state):
        logging.info("New SocketConnection object is created - addr: {}".format(address))
        self.fd = fileno
        self.conn = conn
        self.address = address
        self.connection_state = connection_state
        self.room_num = ""
        self.verified = False #this field is used to verify that only the allowed users can be connected to the server
        self.user_id = str(uuid.uuid4()) #unique user id that is regenerated everytime a new socket is connected
        self.user_name = ""
        self.user_blocked = [] #a list for blocked users which won't match

    def addUserBlock(self, user_id):
        self.user_blocked.append(user_id)
        
###

logging.Formatter.converter = time.gmtime
log_file_name = time.strftime("%m-%d-%Y-%I:%M:%S-%p") + "-log.txt"
logging.basicConfig(format='%(asctime)s [%(filename)s:%(funcName)s:%(lineno)d] - %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', filename = "logs/"+log_file_name, level = logging.DEBUG)


Maximum_Socket_Allowed = 1000 #only allow upto 1000 connection

all_sockets = {} # dict with {fileno : socket}
all_chat_rooms = {} #dict whose key is chat room num and value is tuple that contain two connected sockets in a chat room

host_addr = "127.0.0.1"
#host_addr = "Your domain"

lock = threading.Lock()

#Main Socket I/O function
def main():
    
    #--Main--
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host_addr, 1060))
    sock.listen(50)

    #Create a poll so that it can process connections asyncrhonously
    poll_object = select.poll()
    poll_object.register(sock)


    serverSocket = SocketConnection(sock.fileno(), sock, host_addr + "1060", socket_connection_state_in_lobby)

    all_sockets[serverSocket.fd] = serverSocket

    #all_sockets[sock.fileno()] = sock
    #addresses[sock.fileno()] = host_addr + "1060"

    for fd, event in observe_events(poll_object):
        received_sock = all_sockets.get(fd, None)
        #logging.info("Event received - fd: {}, event: {}".format(fd, event))

        if received_sock is None:
            logging.info("Unregisted sock received - fd: {}".format(fd))
            continue

        received_conn = all_sockets.get(fd, None).conn
        address = all_sockets[fd].address
        
        if event & (select.POLLHUP | select.POLLERR | select.POLLNVAL):
            #Error found - or disconnected
            logging.info("connection was closed due to error event: {} - address: {}".format(event, address))

            remove_socket_from_server(poll_object, received_sock)

            #broadcast that a user has left
            user_num = get_connected_user_number()            
            json_data = create_user_num_json_data(user_num)
            broadcast_message(json_data, exceptions=[sock.fileno(), received_conn.fileno()])
            
            continue
        
        elif received_conn is sock:
            #new socket connection was found
            conn, addr = sock.accept()
            conn.settimeout(0.0)
            #logging.info("New connection was accepted - address: {}, socket: {}".format(addr, conn))
            new_sock = SocketConnection(conn.fileno(), conn, addr, socket_connection_state_in_lobby)

            #logging a list of connectors
            f = open("connectors.txt", "a+")
            f.write("Connection was made with: {}\n".format(addr))
            f.close()

            #check if socket num reahced the limit, if so disconnect the socket
            if len(all_sockets) >= Maximum_Socket_Allowed:
                send_server_has_no_room(new_sock)
                continue
            
            all_sockets[conn.fileno()] = new_sock
            poll_object.register(conn, select.POLLIN)

            logging.info("Current connected socket num (including listening socket): {}".format(len(all_sockets)))

            #ask a verification question
            send_verification_question(new_sock)  

            #broadcast that a new user has been connected to the users in lobby
            user_num = get_connected_user_number()            
            json_data = create_user_num_json_data(user_num)
            broadcast_message(json_data, exceptions=[new_sock.fd, received_conn.fileno()])

        elif event & select.POLLIN:
            #data to receive
            data = received_conn.recv(4096)

            if len(data) == 0:
                #ignore empty data and check if the connection is still alive by sending data out
                poll_object.modify(fd, select.POLLOUT)
                continue
            
            logging.info("Data received from {}: {}".format(address, data))

            valid_str = get_valid_data(data)

            if valid_str == "":
                continue

            if received_sock.verified == False:
                #If the user was not verified it needs to be verified first. If failed, disconnect the connection
                verified = process_received_verification_data(received_sock, valid_str)
                if verified == False:
                    remove_socket_from_server(poll_object, received_sock)
                    continue
                logging.info("Verification Status: {}".format(verified))
            
            purpose, sender, message, logid = decode_message_json(valid_str)

            if purpose == None or purpose == "":
                logging.info("Data received contains incorrect data - ignore the message")
                continue

            #process data according to the purpose of the message received
            if purpose == purpose_user_num:
                user_num = get_connected_user_number()
                logging.info("current user number request: {}".format(user_num))
                json_data = create_user_num_json_data(user_num)
                send_message_to_socket(fd, json_data)
                
            elif purpose == purpose_chat_message:
                sender_socket = all_sockets[fd]
                if sender_socket.connection_state == socket_connection_state_in_chatroom:
                    #send the message to the other person
                    room_num = sender_socket.room_num
                    logging.info("Room number for the message: {} - {}".format(message, room_num))
                    socketTuple = all_chat_rooms.get(room_num)
                    if socketTuple == None:
                        logging.info("Socket tuple is None here - something went wrong")
                        continue
                    receiver_fd = socketTuple[0].fd if socketTuple[1].fd == fd else socketTuple[1].fd
                    json_data = create_chat_room_message_json_data(message, fd)
                    send_message_to_socket(receiver_fd, json_data)
                
            elif purpose == purpose_connect_chat_room:
                
                #match with waiting sockets
                match_socket_for_chatroom(lock, received_sock)
                json_data = create_join_chat_room_json_data(False, "", "")
                send_message_to_socket(fd, json_data)
                
            elif purpose == purpose_leave_chat_room:
                #make the socket leave the chat room and remove the other socket as well and notify them
                sender_socket = all_sockets.get(fd)
                if sender_socket == None:
                    continue
                leave_chat_room(sender_socket)

            elif purpose == purpose_cancel_chat_room_connection:
                cancel_chat_room_connection(received_sock)
            elif purpose == purpose_change_user_name:
                user_name = decode_user_name_change_message_json(valid_str)
                received_sock.user_name = user_name
                
            #utilities
            elif purpose == purpose_utility_get_all_sockets:
                json_data = create_get_all_sockets_json_data()
                send_message_to_socket(fd, json_data)
                logging.info("get all sockets response was sent to socket - {}".format(received_sock))

            #report user
            elif purpose == purpose_report_user:

                (reporter, user_id, user_name, details) = decode_report_user_message_json(valid_str)

                reportedSock = get_sock_with_user_id(user_id)
                
                if reportedSock == None:
                    #Room doesn't exist anymore
                    continue

                #unicode is not available in the default Ubuntu
                try:
                    reporter.encode("ascii")
                except:
                    reporter = ""

                try:
                    user_name.encode("ascii")
                except:
                    user_name = ""

                try:
                    details.encode("ascii")
                except:
                    details = ""

                reportStr = "\n---New User Report---\nReporter: {}, {}\nReported user: {}, {}\nDetails: {}\n".format(reporter, received_sock.address, user_name, reportedSock.address, details)
                f = open("reportedUsers.txt", "a+")
                f.write(reportStr)
                f.close()
                
            #block user
            elif purpose == purpose_block_user:
                user_id = decode_block_user_message_json(valid_str)
                otherSock = get_sock_with_user_id(user_id)
                received_sock.addUserBlock(user_id)
                #also add the block this user in the blocked user's list so they don't match each other
                otherSock.addUserBlock(received_sock.user_id)
                
        elif event & select.POLLOUT:
            #data to send
            try:
                byte_sent = received_conn.send(b"Connection checking")
                #logging.info("Byte sent: {}".format(byte_sent))
                if byte_sent == 0:
                    #disconnect the socket since the connection seems broken
                    remove_socket_from_server(poll_object, received_sock)
                    continue
                poll_object.modify(fd, select.POLLIN)
            except:
                continue
            
#execute main!!!
if __name__ == "__main__":
   try:
      main()
   except Exception as e:
      logging.exception("main crashed. Error: %s", e)
