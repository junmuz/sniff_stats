

void state_update(struct flow_param * flow_this, struct tcphdr *tcph)
{
	switch(flow_this->state) {
		case 0:							//Initial State
			if(tcph->syn & ~tcph->ack) {
				flow_this->state = 1;			//Client SYN state
			}
			break;

		case 1:							// SYN-ACK state
			if(tcph->syn & tcph->ack) {
				flow_this->state = 2;
			}
			break;

		case 2:						
			if(~tcph->syn & tcph->ack & ~tcph->fin) {	//S.ACK state
				flow_this->state = 3;
			}
			else if(~tcph->syn & tcph->ack & tcph->fin){	//F.ACK state				
				flow_this->state = 4;
			}
			break;

		case 3:						
			if(~tcph->syn & tcph->fin) {
				flow_this->state = 4;
			}
			break;

		case 4:
			if(~tcph->syn & tcph->fin & tcph->ack) {
				flow_this->state = 5;
			}
			break;

		case 5:
			if(~tcph->syn & tcph->ack) {
				flow_this->state = 6;
			}
			break;

		default:
			flow_this->state = 6;
			break;
	}

}
