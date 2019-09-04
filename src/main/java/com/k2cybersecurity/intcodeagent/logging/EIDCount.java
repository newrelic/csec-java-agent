package com.k2cybersecurity.intcodeagent.logging;

import java.util.Iterator;
import java.util.concurrent.ConcurrentLinkedDeque;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

public class EIDCount {

	private Long eid;

	private Long count;
	
	public EIDCount() {
	}

	/**
	 * @return the eid
	 */
	public Long getEid() {
		return eid;
	}

	/**
	 * @param eid the eid to set
	 */
	public void setEid(Long eid) {
		this.eid = eid;
	}

	/**
	 * @return the count
	 */
	public Long getCount() {
		return count;
	}

	/**
	 * @param count the count to set
	 */
	public void setCount(Long count) {
		this.count = count;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((eid == null) ? 0 : eid.hashCode());
		return result;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!(obj instanceof EIDCount))
			return false;
		EIDCount other = (EIDCount) obj;
		if (eid == null) {
			if (other.eid != null)
				return false;
		} else if (!eid.equals(other.eid))
			return false;
		return true;
	}

	/**
	 * @param eid
	 * @param count
	 */
	public EIDCount(Long eid, Long count) {
		super();
		this.eid = eid;
		this.count = count;
	}

	public static EIDCount find(Long eid, ConcurrentLinkedDeque<EIDCount> eidCounts) {
		Iterator<EIDCount> eiDIterator = eidCounts.descendingIterator();
		while (eiDIterator.hasNext()) {
			EIDCount eidCount = eiDIterator.next();
			if (eidCount.getEid() <= eid)
				return eidCount;
		}
		return null;
	}

	public static synchronized boolean removeEidCount(EIDCount eidCount, ConcurrentLinkedDeque<EIDCount> eidCounts) {
		return eidCounts.remove(eidCount);
	}
	
	public Long increment() {
		this.count+=1;
		return this.count;
	}

	public Long decrement() {
		this.count-=1;
		return this.count;
	}
	
	@Override
	public String toString() {
			return JsonConverter.toJSON(this);
	}

}
